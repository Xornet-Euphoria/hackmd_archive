---
tags: ctf
---

# redpwnCTF 2020 - SMarT-Solver

問題のリポジトリ: <https://github.com/redpwn/redpwnctf-2020-challenges>
これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

よくあるCrackme。フラグ中の任意の文字ペアとの比較式が文字数分存在することからmain関数はアホみたいに大きく、Ghidraデコンパイルは効かない(エラーを吐く)
が、大して複雑なアセンブリ言語は使われていないので該当部分をcapstoneを使ってパースし、条件式を列挙する。
後はこの条件式達をz3に流し込むだけで終わる

### Binary

Ghidraで覗くとmain関数がデカ過ぎてデコンパイル出来ないのでアセンブリを直接読む

```
        0010085b 48 89 e5        MOV        RBP,RSP
        0010085e 53              PUSH       RBX
        0010085f 48 81 ec        SUB        RSP,0x138
                 38 01 00 00
        00100866 89 bd cc        MOV        dword ptr [local_13c + RBP],EDI
                 fe ff ff
        0010086c 48 89 b5        MOV        qword ptr [local_148 + RBP],RSI
                 c0 fe ff ff
        00100873 64 48 8b        MOV        RAX,qword ptr FS:[0x28]
                 04 25 28 
                 00 00 00
        0010087c 48 89 45 e8     MOV        qword ptr [RBP + local_20],RAX
        00100880 31 c0           XOR        EAX,EAX
        00100882 48 8d 3d        LEA        RDI,[s_Welcome_to_SMarT_solver!_The_#1_s_00122   = "Welcome to SMarT solver!\nThe
                 4f 27 02 00
        00100889 e8 42 fe        CALL       puts                                             int puts(char * __s)
                 ff ff
        0010088e 48 8d 3d        LEA        RDI,[s_Enter_a_flag:_00123020]                   = "Enter a flag: "
                 8b 27 02 00
        00100895 b8 00 00        MOV        EAX,0x0
                 00 00
        0010089a e8 61 fe        CALL       printf                                           int printf(char * __format, ...)
                 ff ff
        0010089f 48 8d 85        LEA        RAX=>local_128,[-0x120 + RBP]
                 e0 fe ff ff
        001008a6 ba 00 01        MOV        EDX,0x100
                 00 00
        001008ab be 00 00        MOV        ESI,0x0
                 00 00
        001008b0 48 89 c7        MOV        RDI,RAX
        001008b3 e8 58 fe        CALL       memset                                           void * memset(void * __s, int __
                 ff ff
        001008b8 48 8b 15        MOV        RDX,qword ptr [stdin]
                 51 37 22 00
        001008bf 48 8d 85        LEA        RAX=>local_128,[-0x120 + RBP]
                 e0 fe ff ff
        001008c6 be 00 01        MOV        ESI,0x100
                 00 00
        001008cb 48 89 c7        MOV        RDI,RAX
        001008ce e8 4d fe        CALL       fgets                                            char * fgets(char * __s, int __n
                 ff ff
        001008d3 48 8d 85        LEA        RAX=>local_128,[-0x120 + RBP]
                 e0 fe ff ff
        001008da 48 89 c7        MOV        RDI,RAX
        001008dd e8 fe fd        CALL       strlen                                           size_t strlen(char * __s)
                 ff ff
        001008e2 48 83 e8 01     SUB        RAX,0x1
        001008e6 0f b6 84        MOVZX      EAX,byte ptr [-0x120 + RBP + RAX*0x1]
                 05 e0 fe 
                 ff ff
        001008ee 3c 0a           CMP        AL,0xa
        001008f0 75 1b           JNZ        LAB_0010090d
        001008f2 48 8d 85        LEA        RAX=>local_128,[-0x120 + RBP]
                 e0 fe ff ff
        001008f9 48 89 c7        MOV        RDI,RAX
        001008fc e8 df fd        CALL       strlen                                           size_t strlen(char * __s)
                 ff ff
        00100901 48 83 e8 01     SUB        RAX,0x1
        00100905 c6 84 05        MOV        byte ptr [-0x120 + RBP + RAX*0x1],0x0
                 e0 fe ff 
                 ff 00
                             LAB_0010090d                                    XREF[1]:     001008f0(j)  
        0010090d 48 8d 85        LEA        RAX=>local_128,[-0x120 + RBP]
                 e0 fe ff ff
        00100914 48 89 c7        MOV        RDI,RAX
        00100917 e8 c4 fd        CALL       strlen                                           size_t strlen(char * __s)
                 ff ff
        0010091c 48 83 f8 48     CMP        RAX,0x48
        00100920 0f 86 9c        JBE        LAB_0011b9c2
                 b0 01 00

```

大した事は無く、入力を促した後に入力長が0x48より長いかを判定している、入力は`local_128(rbp - 0x120)`に入る。
これに続いて次のような命令が羅列している

```
        00100926 0f b6 95        MOVZX      EDX,byte ptr [local_128 + RBP]
                 e0 fe ff ff
        0010092d 0f b6 85        MOVZX      EAX,byte ptr [local_127 + RBP]
                 e1 fe ff ff
        00100934 38 c2           CMP        DL,AL
        00100936 0f 83 8c        JNC        LAB_0011b9c8
                 b0 01 00
```

`local_n + RBP`は`rbp - n + 8`を指す(Ghidraの仕様で8だけずれているのは謎)。以後こんな調子で`local_e0`まで続いておりこの単位だと5028個もある、そりゃGhidraのデコンパイラも匙を投げるわけだ

使用コード中でassertionを掛けているが、この4つの命令はかなり規則的で次のようになっている

1. `movzx edx, byte ptr [rbp - <n1>]`: 入力のあるインデックスにある文字をedxに入れる
2. `movzx eax, byte ptr [rbp - <n2>]`: 入力のあるインデックスにある文字をeaxに入れる
3. `cmp dl, al`: それらを比較する
4. `jbe|jnc|jae <failure label>`: それぞれ`dl <= al`, `dl >= al`, `dl >= al`に引っ掛かったらラベルへジャンプする(飛んだ先でも直ぐにjumpし、そこでフラグの形式を満たさない旨が表示される)

というわけで1, 2でどのインデックスが選ばれたかさえ判明すれば4の条件の否定となる条件を選ぶことで各文字(のアスキーコード)同士の大小関係が判明する

### Capstone

Capstoneというクソ便利な逆アセンブラが存在する。pythonでも簡単に利用することが出来、バイト列を与えるとそれを逆アセンブルしてくれる。
今回は前述の文字比較部分がどのアドレスにあるか分かっているのでそれらのバイト列を与えることで逆アセンブルし、その結果をパースすることでインデックスと条件を特定する
入力の先頭はrbp - 0x120なので`rbp - n`の場合は`0x120 - n`文字目が比較されることになる。
ジャンプに使われる命令は`jbe, jnc, jae`の3通りであり、コードのコメントに記したフラグの状況からそれぞれ`dl <= al`, `dl >= al`, `dl >= al`の時にジャンプする。この条件を回避すれば良いのでそれぞれ`dl > al`, `dl < al`, `dl < al`になる。
比較インデックスと条件が確定したので後はこれをz3の条件として加える

### z3

z3という超優秀なSMTソルバーがあるので今回はこれを使う。逆アセンブルで判明した条件とフラグは全部小文字と波括弧という条件(問題説明より)があるのでこれを全部加えてソルバーを走らせる。

## Code

```python=
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from z3 import BitVec, Solver


prefix_length = len("edx, byte ptr [rbp - 0x")


def parse_constraint(constr):
    i1 = 0x120 - int(constr[0][1][prefix_length:-1], 16)
    i2 = 0x120 - int(constr[1][1][prefix_length:-1], 16)
    jmp_mne = constr[3][0]

    return (i1, i2, jmp_mne)


if __name__ == '__main__':
    with open("./SMarT-solver", "rb") as f:
        elf = f.read()

    start_offset = 0x926
    end_offset = 0x1b93e

    texts = elf[start_offset: end_offset]
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    mnemonic_list = ["movzx", "cmp", "jbe", "jnc", "jae"]
    constraints = []
    constr = []
    for i, m in enumerate(md.disasm(texts, start_offset)):
        # assertion
        assert m.mnemonic in mnemonic_list
        if i % 4 == 0 or i % 4 == 1:
            assert m.mnemonic == "movzx"
        if i % 4 == 0:
            assert m.op_str[0:prefix_length] == "edx, byte ptr [rbp - 0x"
        elif i % 4 == 1:
            assert m.op_str[0:prefix_length] == "eax, byte ptr [rbp - 0x"
        elif i % 4 == 2:
            assert m.mnemonic == "cmp"
            assert m.op_str == "dl, al"
        elif i % 4 == 3:
            assert m.mnemonic[0] == "j"

        constr.append([m.mnemonic, m.op_str])
        if i % 4 == 3:
            constraints.append(parse_constraint(constr))
            constr = []

    print(len(constraints))

    l = 73
    v = [BitVec(f"c_{i}", 8) for i in range(l)]
    s = Solver()
    for i in range(l):
        s.add(v[i] > 0x60)
        s.add(v[i] < 0x7e)
        s.add(v[i] != 0x7c)

    for c in constraints:
        """
            - jbe: cf == 1 | zf == 1 -> dl <= al
            - jnc: cf == 0 -> dl >= al
            - jae: cf == 0 -> dl >= al

            - cf == 1: dl < al
            - cf == 0: dl >= al
            - zf == 1: dl == al
        """
        # print(c[0], c[1])
        i_dl = c[0]
        i_al = c[1]
        jmp_mne = c[2]

        if jmp_mne == "jbe":
            s.add(v[i_dl] > v[i_al])
        elif jmp_mne == "jnc":
            s.add(v[i_dl] < v[i_al])
        elif jmp_mne == "jae":
            s.add(v[i_dl] < v[i_al])

    if str(s.check()) == "unsat":
        print("ha?")
        exit()

    m = s.model()
    flag = ""
    for i in v:
        flag += chr(m[i].as_long())

    print(flag)
```

## Flag

`flag{thequickbrownfoxjumpedoverthelazydogandlearnedhowtoautomateanalysis}`

念の為配布バイナリでバリデーションしておく

```
$ ./SMarT-solver 
Welcome to SMarT solver!
The #1 solution for your flag checking needs.

Enter a flag: flag{thequickbrownfoxjumpedoverthelazydogandlearnedhowtoautomateanalysis}

Correct input!
```

問題ないようである

## 感想

redpwnCTF 2020当日ではCryptoの問題でz3を初めて使いましたがRevの問題で使ったのはこれが初めてでした(この問題は別のチームメイトが解いた)。
Capstoneやz3等、便利なツールの存在を直ぐに思い出して使うことが出来たので良かったです