---
tags: crypto, ctf
---

# Crypto CTF 2020 - Model

## Writeup

### Outline

セッションごとに鍵が変わるRSA問題、だが`n (= p*q)`しか開示されない(`e`が不明なまま)。一応任意の平文を暗号化出来る(そもそもRSAは選択平文攻撃に耐性が無くてはならない)。ついでにフラグを暗号化したものもくれる。
`e`の作り方がかなり特殊なので暗号化機能を使って適当な平文を暗号化し、これを上手く式変形すると1より大きい`n`の公約数を持つ値が手に入る、つまり`n`の素因数分解が出来る。
後は`e`の作り方が、`p, q`に依存するので`e`を求めて、`p, q`も分かっているので秘密鍵`d`を求めてフラグを復号すれば良い。

### 暗号化と鍵生成コード

```python=
def genkey(nbit):
    while True:
        p, q = getPrime(nbit), getPrime(nbit)
        if gcd((p-1) // 2, (q-1) // 2) == 1:
            P, Q = (q-1) // 2, (p-1) // 2
            r = inverse(Q, P)
            e = 2 * r * Q - 1
            return(p, q, e)


def encrypt(msg, pubkey):
    e, n = pubkey
    return pow(bytes_to_long(msg), e, n)
```

暗号化はタダのRSAだが、鍵生成部分において明らかに`e`の作り方がおかしい。`genkey`を数式で表すと次のようになる。

$$
P, Q = \frac{q-1}2, \frac{p-1}2 \\
rQ \equiv 1 \mod P \\
e = 2rQ - 1
$$

$rQ$ が合同式の形になっているのでこれを外すと次のようになる。

$$
rQ - 1 = k \cdot \frac{q-1}2
$$

これを $e$ の式に代入すると $e = k(q-1) + 1$ になる。 $k$ はある整数だが、以後同様に合同式を外す事があるのでこれを $k_e$ とおいて $e$ を次のように書き直す

$$
e = k_e(q-1) + 1
$$

フラグを $m$ とおくとこの暗号化は次のようになる。

$$
c \equiv m^e = m^{k_e(q-1) + 1} \mod pq
$$

よってこれもまた合同式を外し、暗号文を $q$ で割ると次のようになる。

$$
m^{k_e(q-1) + 1} = k_n pq + c = q(k_np + c') + c_q \\
c = qc' + c_q
$$

ここでフェルマーの小定理から $m^{k_e(q-1) + 1} \equiv m \mod q$ であるので先程の $q$ で割った式は次のようになる。

$$
m \equiv c_q \mod q
$$

これもまた合同式を外すと $c_q = m + k'q$ のようになる。これを $c$ を $q$ で割った式に代入すると $c = qc' + m + k'q$ であるから、 $c - m = (c' + k')q$ である。

この問題では任意の平文を暗号化出来るので $c, m$ は既知である。更に $n = pq$ は手に入るので、 $n, c-m$ の公約数を求めると $q$ が手に入ることが期待できる。
ここまで来れば $n / q$ を求める事で $p$ も手に入るので後は`genkey`関数同様に $e$ を求めて、RSAの秘密鍵生成手順を経る事で秘密鍵も求め、復号するだけである。

## Code

※解いた時は $p, q$ を逆に考えていたのでこのコードもそんな感じになってます

```python=
from pwn import remote
from hashlib import sha224, sha1, md5, sha256, sha512, sha384
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
from xcrypto import gcd, dec_pq
from xlog import XLog


pow_funcs = {
    "sha224": sha224,
    "sha512": sha512,
    "sha256": sha256,
    "sha1": sha1,
    "md5": md5,
    "sha384": sha384
}


logger = XLog("EXPLOIT")


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


def get_key(s):
    sel(s, "P")
    s.recvuntil("n = ")
    return int(s.recvline().rstrip())


def get_flag(s):
    sel(s, "C")
    s.recvuntil("encrypt(flag, pubkey) = ")
    return int(s.recvline().rstrip())


def encrypt(s, msg):
    sel(s, "T")
    s.recvuntil("please send your msg:")
    s.sendline(msg)
    s.recvuntil(") =  ")
    return int(s.recvline().rstrip())


def calc_e(p, q):
    assert gcd((p - 1) // 2, (q - 1) // 2) == 1
    P, Q = (q - 1) // 2, (p - 1) // 2
    r = inverse(Q, P)
    e = 2 * r * Q - 1
    return e


if __name__ == '__main__':
    target = "04.cr.yp.toc.tf"
    port = 8001

    sc = remote(target, port)

    proof_of_work(sc)
    n = get_key(sc)
    enc = get_flag(sc)

    m = b"114514"
    c = encrypt(sc, m)
    m = bytes_to_long(m)

    p = gcd(c - m, n)
    assert n % p == 0
    q = n // p

    e = calc_e(q, p)

    flag = dec_pq(enc, p, q, e)

    logger.info(long_to_bytes(flag))

    sc.close()

```

## Flag

`CCTF{7He_mA1n_iD34_0f_pUb1iC_key_cryPto9raphy_iZ_tHa7_It_l3ts_y0u_puBli5h_4N_pUbL!c_k3y_wi7hOuT_c0mprOmi5InG_y0Ur_5ecr3T_keY}`

## 感想

RSAの式変形ゲーが好きなので[Crypto CTF 2020 - Gambler](/@Xornet/Sk1eXeKNP)の方が難しく感じました。