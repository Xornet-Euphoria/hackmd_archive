---
tags: crypto, ctf
---

# Crypto CTF 2020 - Gambler

* 会場: <https://cryp.toc.tf/>
* これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

暗号化関数`enc(m) := f(m) % p`が用意されており、暗号化のコードと与えた数値に対する暗号化結果が与えられる。
`enc`は法が設定されているが平文が小さい時に無視出来るため0, 1を指定して係数を入手する。
また、pも`f(m) = enc(m) + p`となるような`m`を選べば導出出来る
その結果をSageMathの`roots`メソッドを使って導出する

### 暗号化関数入手

とりあえずPoWがあるので突破する。すると次のようなメニューが現れる

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+ Hi, there is a strong relation between philosophy and the gambling!  +
+ Gamble as an ancient philosopher and find the flag :)                +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
| Options: 
|    [C]ipher flag! 
|    [E]ncryption function! 
|    [T]ry the encryption 
|    [Q]uit
```

`E`を打ち込むと次のような結果が得られる

```python=
def encrypt(m, p, a, b):
    assert m < p and isPrime(p)
    return (m ** 3 + a * m + b) % p
```

### 係数導出

`encrypt`は`m=0`とすると`b % p`が得られそうである。更に`m=1`とすると`(1 + a + b) % p`が得られそうである。
よってこの2つの結果から`a, b`は手に入ることが期待出来る(以降の復号を何度かやって失敗したので運ゲーではあるが現実的な試行回数でいける)

### 法導出

後は法がわかれば暗号化関数を入手することが出来、これは法を`p`とする3次方程式なのでSageMathの`roots`メソッドに投げたらなんとかなるかもしれない。
ここで暗号文`c`に対して次のような関係が成り立つ

$$
c \equiv x^3 + ax + b \mod p
$$

合同を外すと

$$
x^3 + ax + b = kp + c
$$

$x$ が小さい時、 $k$ も小さくなることが期待される。よって $k=1$ になりそうな $x$ を暗号化すればその結果と上記で求めた係数を合わせて $p$ を入手出来そうである。
今回は $a, b$ が $p$ と似たようなビット数なので比較的小さい $x$ でも条件を満たすことから $x^3 + ax + b > c$ を初めて満たす $x$ をインクリメントしながら探した。

### 根導出

SageMathの`roots`メソッドは与えた多項式の根を計算してくれる凄いやつなのでここまでで手に入れたパラメータで多項式環と多項式を定義し、こいつを叩いて解を求める。

## Code

### 係数と法の導出

```python=
from pwn import remote
from hashlib import sha224, sha1, md5, sha256, sha512, sha384
from random import choices
from string import printable, whitespace
from xlog import XLog
from Crypto.Random import get_random_bytes


pow_funcs = {
    "sha224": sha224,
    "sha512": sha512,
    "sha256": sha256,
    "sha1": sha1,
    "md5": md5,
    "sha384": sha384
}


logger = XLog("EXPLOIT")


str_table = printable[: -len(whitespace)]


def pad(s, n):
    if len(s) > n:
        raise ValueError

    s = s.rjust(n, "0")

    return s


def proof_of_work(s):
    s.recvuntil("such that ")
    f = s.recvuntil("(")[:-1].decode()
    f = pow_funcs[f]

    s.recvuntil("[-6:] = ")
    sub_hex = s.recvuntil(" ")[:-1].decode()

    s.recvuntil("len(X) = ")
    l = int(s.recvline().rstrip())

    logger.info(f"required: {f}, {sub_hex}, {l}")

    i = 0
    while True:
        r = pad(str(i), l)
        res = f(r.encode()).hexdigest()
        if res[-6:] == sub_hex:
            break

        i += 1

        if i % 1000000 == 0:
            logger.info(f"{i}, {r}, {res}")

    logger.info(f"done: {r} -> {res}, {sub_hex}")

    s.sendline(r)


def sel(s, sel, c="[Q]uit\n"):
    s.recvuntil(c)
    s.sendline(sel)


def get_flag(s):
    sel(s, "C")
    s.recvuntil("encrypt(bytes_to_long(flag)) = ")
    return int(s.recvline().rstrip())


def encrypt(s, n):
    sel(s, "T")
    s.recvuntil("encrypt:\n")
    s.sendline(str(n))
    s.recvuntil(") = ")
    return int(s.recvline().rstrip())


def f(a, b, x):
    return x**3 + a*x + b


if __name__ == '__main__':
    target = "05.cr.yp.toc.tf"
    port = 33371
    s = remote(target, port)
    
    proof_of_work(s)

    """
        | Options: 
        |    [C]ipher flag! 
        |    [E]ncryption function! 
        |    [T]ry the encryption 
        |    [Q]uit
    """

    enc = get_flag(s)
    print(enc)
    b = encrypt(s, 0)
    a = encrypt(s, 1) - b - 1

    x = 2
    while True:
        res = encrypt(s, x)
        if f(a, b, x) > res:
            break
        x += 1

    p = f(a, b, x) - res

    print("a =", a)
    print("b =", b)
    print("p =", p)
    print("enc =", enc)

    s.close()

```

### 根の導出(sage)

```python=
# from above python script
a = 4961811968004061397900693704963755234659151244896550508323058459675696462276684305533635465493837436260875704912554716748325967624113298353109669742630195
b = 912506603028728950371141514247010737680190004349199201490288937398517500325731886343978577159598279786856287999581063624131319450833835197075700687743632
p = 7259594276937950997934503824538029621277738842224181563016649940121276709295805254951826139204148405305506569748384559542403022711176479386631237036993603
enc = 4385601246549072141048692141943489679810123725977560589312588040606030372604063936913847316691625032658380146839594460819087192014610271506477790971825928

K = Zmod(p)
PR.<x> = PolynomialRing(K)

f = x^3 + a*x + b - enc

res = f.roots()[0][0]

print(res)
```

`long_to_bytes`入れるの忘れたので別(pythonの対話環境)でフラグを出しました

## Flag

`CCTF{__Gerolamo__Cardano_4N_itaLi4N_p0lYma7H}`

## 感想

SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!SageMath最強!!

地味にpを求める際の成功可能性を検証したりして無駄な時間を過ごした。こういうのは難しいこと考えず「えいっ!!」ってやって失敗が連続したら考え直すぐらいのほうが良いのかもしれない