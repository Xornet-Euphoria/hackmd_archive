---
tags: crypto, ctf
---

# InterKosenCTF 2020 - padrsa

* 問題が含まれるCTFのリポジトリ: <https://github.com/theoremoon/InterKosenCTF2020-challenges>
* 運営のWriteup: <https://hackmd.io/@ptr-yudai/B16_IEl9I>
* これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

こちらが与えた平文がフラグにパディングを施し、RSAで暗号化するシステムが動いている。
`3 <= e <= 65537`の範囲で`e`を指定することが出来、パディングによって非常に長くなることも無いため、短い平文で小さい`e`を指定すればその結果の`e`乗根を取ることでパディングを特定することが出来る。
また、パディングは暗号化毎に更新されるが、前の暗号化のパディングに依存するので一度パディングを特定すれば以後のパディングは完全に特定可能になる。
これでパディングを施すと元の平文以外の部分が判明するので同じ平文を暗号化する際、パディング後の差は判明する。
したがってFranklin-Reiter Related Message Attackを適用することが出来るのでこれを使って平文を求める。

### rの特定

[CTF終了後に書いたWriteup](https://hackmd.io/@Xornet/r1TUJXf4D#%E3%83%81%E3%83%BC%E3%83%A0%E3%83%A1%E3%82%A4%E3%83%88%E4%BB%A3%E7%90%86padrsa)と全く同じ

### Franklin-Reiter Related Message Attack

ある平文 $m_1, m_2$ を暗号化することを考える。ここで2つの平文はパディングが違うだけで元は同じ、といった状況で差がわかるものとする。つまり $m_2 \equiv am_1+b := f(m_1) \mod n$ のような形で現されるとする。
これらを暗号化すると次のようになる

$$
c_1 \equiv m_1^{e_1} \mod n \\
c_2 \equiv m_2^{e_2} \mod n
$$

この内、下部の式から $m_2$ を消去して $m_1$ の式にすると次のようになる。

$$
c_2 \equiv f(m_1)^{e_2} = (am_1 + b)^{e_2} \mod n
$$

ということで解が $m_1$ の次のような2つの合同方程式が得られる

$$
g_1(x) := x^{e_1} - c_1 \equiv 0 \mod n \\
g_2(x) := (ax + b)^{e_2} - c_2 \equiv 0 \mod n
$$

$g_1, g_2$ 共に $x=m_1$ が解となるので $g_1(x) \equiv (x - m_1)h_1(x) \mod n$ や $g_2(x) \equiv (x - m_1)h_2(x) \mod n$ が成り立つはずである。
この公約式 $x - m_1 \mod n$ を求めることでパディング付きの平文 $m_1$ を入手することが出来る。

今回はフラグ $flag$ に対しパディングを施すので $m := flag * (256)^8$ とすると

$$
m_1 = pad_1 + m \\
m_2 = pad_2 + m
$$

が成り立つので $m_2 = m_1 + (pad_2 - pad_1)$ の形で表すことが出来る。つまり $f(x) = x + (pad_2 - pad_1)$ である。
最初にパディングの初期パラメータを求めたので $pad_1, pad_2$ は既知である。よってこの攻撃を使うことが出来る。

## Code

### 各種パラメータ導出(Python)

```python=
from pwn import remote
from binascii import unhexlify, hexlify
from Crypto.Util.number import bytes_to_long, long_to_bytes
from xcrypto import int_nth_root, crt


def select(s, sel, c=b"> "):
    s.recvuntil(c)
    s.sendline(str(sel))


def recv_and_unhex(s):
    s.recvuntil(b"c: ")
    raw_res = s.recvline().rstrip()
    res = bytes_to_long(unhexlify(raw_res))

    return res


def enc_flag(s, e):
    select(s, 1)
    s.recvuntil(b"e: ")
    s.sendline(str(e))
    return recv_and_unhex(s)


def enc_msg(s, e, msg):
    select(s, 2)
    s.recvuntil(b"e: ")
    s.sendline(str(e))
    s.recvuntil(b"m: ")
    s.sendline(msg)
    return recv_and_unhex(s)


def update_nonce_and_r(nonce, r):
    nonce += 1
    r = long_to_bytes(((bytes_to_long(r) << 1) ^ nonce) & (2 ** 64 - 1))
    
    return nonce, r


if __name__ == '__main__':
    target = "crypto.kosenctf.com"
    port = 13001

    s = remote(target, port)
    s.recvuntil(b"n: ")
    n = int(s.recvline().rstrip())
    print("n =", n)
    res = enc_msg(s, 4, b"10")
    p_root = int_nth_root(res, 4)
    assert p_root ** 4 == res
    r = long_to_bytes(p_root)[2:]
    assert len(r) == 8
    assert long_to_bytes(p_root)[1] == 0x10
    assert long_to_bytes(p_root)[0] == (r[0] | 1)

    nonce = 1

    nonce, r = update_nonce_and_r(nonce, r)
    r_1 = r
    top_1 = (r_1[0] | nonce)
    c_1 = enc_flag(s, 3)
    print("r_1 =", bytes_to_long(r_1))
    print("top_1 =", top_1)
    print("c_1 =", c_1)
    print("e_1 =", 3)

    nonce, r = update_nonce_and_r(nonce, r)
    r_2 = r
    top_2 = (r_2[0] | nonce)
    c_2 = enc_flag(s, 5)
    print("r_2 =", bytes_to_long(r_2))
    print("top_2 =", top_2)
    print("c_2 =", c_2)
    print("e_2 =", 5)

```

### Franklin-Reiter Attack(SageMath)

```python=
from binascii import hexlify, unhexlify
from string import printable


def str_to_num(s):
    return int(hexlify(s), 16)


def num_to_str(s):
    hexed = hex(s)[2:]
    if len(hexed) % 2 == 1:
        hexed = "0" + hexed
    return unhexlify(hexed)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a.monic()


def franklinreiter(c_1, c_2, e_1, e_2, N, a, b):
    P.<X> = PolynomialRing(Zmod(N))
    g_1 = X^e_1 - c_1
    g_2 = (a*X + b)^e_2 - c_2
    # get constant term
    result = -gcd(g_1, g_2).coefficients()[0]

    return result
    

# from python script
n = 6180182076075669553847797352021705161407057822273009211975027847886592187364795585321878201219916214679512948408420492057080029954553687237543072192738343
r_1 = 5655088158697192486
top_1 = 78
c_1 = 5784246907243910588148058033857925015684589827267322084436324323001854593611520452639260633880726806080187381294234527975431737188323643138790562935147493
e_1 = 3
r_2 = 11310176317394384975
top_2 = 159
c_2 = 4765570819063457199521080761532079898191213351230012600594262540387297732107535927511105746243568592475224440637561608638399984817077961474940793569924545
e_2 = 5


for flag_length in range(11, 70):
    print("[+] attempting:", flag_length)
    pad_1 = top_1 * (256 ^ (flag_length+8)) + r_1
    pad_2 = top_2 * (256 ^ (flag_length+8)) + r_2
    diff = pad_2 - pad_1

    plain = num_to_str(franklinreiter(c_1, c_2, e_1, e_2, n, 1, diff))
    if b"KosenCTF{" in plain:
        print(plain)
```

## Flag

当日はチームメイトが解きましたが、鯖が生きていたのとチームメイトが非想定解で解いていたので運営想定解で復習しました

`KosenCTF{p13as3_mak4_padding_unpr3dictab13}`

## 感想

[InterKosenCTF 2020 Writeup](/@Xornet/r1TUJXf4D)でチームメイトの解法を取り上げましたが、こんな感じでズルをして(一般的にCTFはズルをするゲームなので悪口では無い)暗号方面の難易度を下げる非想定解より、暗号自体の地力を問われる想定解で面白かったです。
運営はCryptoボス問を想定して出したそうですが、Pwn的にズルをする非想定解もFranklin-Reiter Attackへ持ち込む想定解もどちらもそこそこ難しく、解法も綺麗だったので非想定解があってもボス問らしいという素晴らしい問題でした。

Franklin-Reiter Attackは何かで読んでその時は頭の片隅に入れていただけでしたが、この問題の復習をきっかけに思い出したのと実装まで漕ぎ着けたので良かったです。今回は使いませんでしたが、この前ステップになることもあるCoppersmith's Short Pad AttackもCTFで出る前に習得しておきたいです。

昨年のInterKosenCTFはCryptoのボス問だけ残して終えてしまい、今回はチームとしては解けたものの私の貢献は無だったので、2年連続でCryptoボス問に敗北したことになります。来年も開催があるならCryptoボス問を倒して三度目の正直を果たしたいです。

## 参考文献

* <https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-Franklin-Reiter>: 実装はだいたいここをパクって異なる`e`に対応するようにした