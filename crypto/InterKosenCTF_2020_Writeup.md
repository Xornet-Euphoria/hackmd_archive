---
tags: ctf
---

# InterKosenCTF 2020 Writeup

## 序文

昨年に引き続きInterKosenCTFに出たのでそのWriteupになります。私はCryptoとRevをちょっとだけ解きました

## ciphertexts

`n_1, n_2`で法が異なるが`n_1 = pq`に対し、`n_2 = pqr`なので、`c_2`を`n_1`で割る事で、`n_1`を法とする暗号化に変換することが出来ることから共通法攻撃が可能。

```python=
from xcrypto import ext_euclid, num_to_str


if __name__ == '__main__':
    n1 = 112027309284322736696115076630869358886830492611271994068413296220031576824816689091198353617581184917157891542298780983841631012944437383240190256425846911754031739579394796766027697768621362079507428010157604918397365947923851153697186775709920404789709337797321337456802732146832010787682176518192133746223
    n2 = 1473529742325407185540416487537612465189869383161838138383863033575293817135218553055973325857269118219041602971813973919025686562460789946104526983373925508272707933534592189732683735440805478222783605568274241084963090744480360993656587771778757461612919160894779254758334452854066521288673310419198851991819627662981573667076225459404009857983025927477176966111790347594575351184875653395185719233949213450894170078845932168528522589013379762955294754168074749
    e1 = 745699
    e2 = 745709

    c1 = 23144512980313393199971544624329972186721085732480740903664101556117858633662296801717263237129746648060819811930636439097159566583505473503864453388951643914137969553861677535238877960113785606971825385842502989341317320369632728661117044930921328060672528860828028757389655254527181940980759142590884230818
    c2 = 546013011162734662559915184213713993843903501723233626580722400821009012692777901667117697074744918447814864397339744069644165515483680946835825703647523401795417620543127115324648561766122111899196061720746026651004752859257192521244112089034703744265008136670806656381726132870556901919053331051306216646512080226785745719900361548565919274291246327457874683359783654084480603820243148644175296922326518199664119806889995281514238365234514624096689374009704546

    c3 = c2 % n1

    s1, s2, _ = ext_euclid(e1, e2)

    res = pow(c1, s1, n1) * pow(c2, s2, n1) % n1

    print(num_to_str(res))

```

### flag

`KosenCTF{HALDYN_D0M3}`

## harmagedon

バイナリ中の文字列中の連続した4文字から1文字選ぶのを11回繰り返す。選んだインデックスを`i`とすると`sum = (sum + i + 1) * 4`というように`sum`が計算され、これが11回目の選択終了後に`0xb77c7c`となるような選択肢を選ぶ

```python=
from itertools import product


if __name__ == '__main__':
    target = 0xb77c7c
    index_list = list(product([0, 1, 2, 3], repeat=11))
    print(len(index_list))

    for idxes in index_list:
        res = 0
        for idx in idxes:
            res = (res + idx + 1) * 4

        if res == target:
            print(idxes)

```

これを実行すると`(1, 2, 0, 2, 0, 2, 1, 3, 0, 2, 2)`という選び方なら条件を満たすことが分かったので後はその通りに入力する。

### flag

`KosenCTF{Ruktun0rDi3}`

## bitcrypto

与えたメッセージがASCIIコードの2進数表記に対応したビットの配列に展開される。
もしビットが0ならサーバー側で定義された`n=pq`に対し、奇素数`p,q`におけるルジャンドル記号がどちらに関しても1である(つまり平方剰余である)数字が配列に追加され、1なら-1である数字が配列に追加される。
これが暗号化手順になる

その配列が渡され、同じ形式で数字の配列を渡すと復号が走り、復号結果が`"yoshiking, give me ur flag"`であればフラグが表示される。
ということはこれらをメッセージの暗号化と同様ビットに展開し、0なら与えたメッセージの0に対応する暗号化配列の数字を、1なら1に対応する数字を配列に入れて送れば認証される。
但し、最初に与えることが出来るメッセージにこれらの文字を含めることは出来ない上に8文字までしか入力出来ない。

ここで復号手順を覗くと次のように実装されている。

```python=
def dec(privkey, c):
    p, q = privkey
    m = ""
    for b in c:
        if legendre_symbol(b, p) == 1 and legendre_symbol(b, q) == 1:
            m += "0"
        else:
            m += "1"
    return int(m, 2)
```

奇素数 $p$ のルジャンドル記号に関して

$$
\left(\frac {ab}p\right) \equiv (ab)^{\frac{p-1}2} = a^{\frac{p-1}2} b^{\frac{p-1}2} = \left(\frac ap\right) \left(\frac bp\right) \mod p
$$

が成り立つ事を利用すれば、使える数字を増やすことが出来る。具体的には0に対応する数字同士、1に対応する数字同士を掛けた数字はサーバー側で0として復号される(ルジャンドル記号が1になる)。
逆にルジャンドル記号が異なる数字同士を掛けた数字は1として復号される(ルジャンドル記号が-1になる)。

```python=
from pwn import remote
from binascii import hexlify, unhexlify
from Crypto.Util.number import *


if __name__ == '__main__':
    target = "crypto.kosenctf.com"
    port = 13003
    s = remote(target, port)
    s.recvuntil(b": ")
    m = b"33333332"  # bitに展開すると0と1が31個ずつ含まれる
    m_long = bytes_to_long(m)
    bits = [int(b) for b in "{:b}".format(m_long)]

    s.sendline(m)
    s.recvuntil(b":  ")
    res = list(map(int, s.recvline().rstrip()[1:-1].split(b", ")))

    zeros = []
    ones = []

    for i in range(len(res)):
        if bits[i] == 0:
            zeros.append(res[i])
        elif bits[i] == 1:
            ones.append(res[i])
        else:
            print("ha?")
            exit()

    append_zeros = []
    append_ones = []

    for n in zeros:
        for m in zeros:
            if n != m:
                append_zeros.append(n * m)

    append_zeros = set(append_zeros)

    for n in ones:
        for m in zeros:
            if n != m:
                append_ones.append(n * m)

    append_ones = set(append_ones)

    keyword = b"yoshiking, give me ur flag"
    k_long = bytes_to_long(keyword)
    k_bits = [int(b) for b in "{:b}".format(k_long)]

    payload = []
    for b in k_bits:
        if b == 0:
            payload.append(append_zeros.pop())
        elif b == 1:
            payload.append(append_ones.pop())
        else:
            print("ha?")
            exit()

    payload = str(payload).replace(" ", "")
    c = [int(x) for x in payload[1:-1].split(",")]
    
    print(c)

    s.recvuntil(b"your token: ")
    s.sendline(payload)
    print(s.recvline().decode())
    print(s.recvline())

```

### Flag

`KosenCTF{yoshiking_is_clever_and_wild_god_of_crypt}`

## padding oracle

padding oracle attackするだけ...と思いきやパディングが下では無く上に付加されるのでそれを考慮したコードを書く必要がある。
padding oracle attackに関する説明は長くなるので省略

```python=
from pwn import remote
from binascii import hexlify, unhexlify


def bytes_xor(b1, b2):
    ret = b""
    l = len(b1)
    for i in range(l):
        res = (b1[i] ^ b2[i]).to_bytes(1, "big")
        ret += res

    return ret


def to_block(s, byte_num=16):
    ret = []
    idx = 0
    l = len(s)
    while idx < l:
        ret.append(s[idx: idx + byte_num])
        idx += byte_num

    if idx != l:
        ret.append(s[idx:])

    return ret


def get_oracle(s, iv, block):
    send_s = hexlify(iv + block)
    
    s.sendline(send_s)
    res = s.recvline().strip()

    return res == b"True"


def get_valid_iv(s, iv, block, idx):
    iv_b_arr = bytearray(iv)
    for c in range(0x100):
        iv_b_arr[idx] = c
        res = get_oracle(s, bytes(iv_b_arr), block)
        if res:
            return bytes(iv_b_arr)

    return None


def fix_block(block, i):
    block_b_arr = bytearray(block)
    for j in range(i):
        block_b_arr[j] = block_b_arr[j] ^ i ^ (i + 1)
        
    return bytes(block_b_arr)


def attack(s, iv, block):
    changed_iv = iv
    for i in range(len(block)):
        print("[+] attempting:", i)
        fixed_iv = fix_block(changed_iv, i)
        changed_iv = get_valid_iv(s, fixed_iv, block, i)
        if changed_iv is None:
            print("ha?")
            exit()

    print(changed_iv)
    plain = bytes_xor(bytes_xor(changed_iv, iv), b"\x10" * 16)
    print(plain)

    return plain


if __name__ == '__main__':
    target = "padding-oracle.kosenctf.com"
    port = 13004
    
    s = remote(target, port)
    res = unhexlify(s.recvline().strip().decode())
    iv = res[:16]
    cipher = res[16:]

    print(iv)
    print(cipher)

    blocks = [iv] + to_block(cipher)
    print(blocks)

    plain_block_num = len(blocks) - 1

    plain = b""
    for i in range(plain_block_num):
        cipher_block_i = -(i + 1)
        iv_block_i = cipher_block_i - 1
        # attack(s, blocks[-2], blocks[-1])
        iv_block = blocks[iv_block_i]
        cipher_block = blocks[cipher_block_i]
        print(iv_block, cipher_block)
        plain += attack(s, iv_block, cipher_block)

    print(plain)
```

### flag

`KosenCTF{0r4c13_5urviv35_57i11_n0w}`

## (チームメイト代理)padrsa

(私は提出していませんが手法を聞いて自前で実装したら解けたので書きます)

`e`をこちらから指定できるという問題。フラグと自分が送ったメッセージを暗号化することが出来る。
Plain RSAではなく、暗号化時にメッセージにパディングが次のようなコードで施される。

```python=
def pad(x: bytes) -> bytes:
    global r, nonce
    y = long_to_bytes(r[0] | nonce) + x + r

    nonce += 1
    r = long_to_bytes(((bytes_to_long(r) << 1) ^ nonce) & (2**64 - 1))
    return y
```

指定できる`e`の範囲は`3 <= e <= 65537`なので、`e`が小さい場合に1文字のメッセージを送ると受け取った暗号文のe乗根を取ることで復号することが出来る。これはパディングを含んでいるのでパディングに使われている`r`を特定することが出来る。

暗号化毎に更新される`nonce`と`r`も手元で計算出来るので`r`が判明して以後の`nonce`と`r`は完全に計算可能である。

さて、`r`の更新に関してはビットシフトが使われているので64回ビットシフトすると`r`の初期値の影響が無くなる。よって最終的に`r`はセッションに関わらず同じ値になると考えられる。これはパディング結果も最終的に同じになることから、同一平文になる事を意味している。

というわけで`n`が異なって同一平文かつ`e`の指定が出来る状況に持ち込めるのでHasted Broadcast Attackが使える。

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

    e = 3
    problem = []

    for _ in range(e):
        s = remote(target, port)
        s.recvuntil(b"n: ")
        n = int(s.recvline().rstrip())
        res = enc_msg(s, 5, b"10")
        p_root = int_nth_root(res, 5)
        assert p_root ** 5 == res
        r = long_to_bytes(p_root)[2:]
        assert len(r) == 8
        assert long_to_bytes(p_root)[1] == 0x10
        assert long_to_bytes(p_root)[0] == (r[0] | 1)
        nonce = 1
        for _e in range(7, 80) :
            nonce, r = update_nonce_and_r(nonce, r)
            top = (r[0] | nonce)
            enc_flag(s, _e)

        nonce, r = update_nonce_and_r(nonce, r)
        top = (r[0] | nonce)
        c = enc_flag(s, e)
        print(bytes_to_long(r), top)

        problem.append([c, n])

    flag = int_nth_root(crt(problem), e)

    print(long_to_bytes(flag))
```

### flag

`KosenCTF{p13as3_mak4_padding_unpr3dictab13}`

## 感想

チームメイトが低レイヤーを軒並み潰していたのでCryptoを久しぶりに解いてました。暗号問題にありがちな「n, e, c, ソースコード」だけを与える問題ではなく、ncで対話的に情報を引き出して解くというのが非常に面白かったです(特にbitcryptoが好きでした)。

padrsaはパディングパラメータがわかることから、Coppersmith's Attackに固執しすぎて自力では解けず、ochazukeも読むか～って言った頃にチームメイトが解いていたので全然貢献できませんでした。そこは残念でしたがチームで全完を達成したらしいので創設者としてかなり嬉しかったです。

Cryptoが式変形に拘り過ぎて条件のバイパス等の発想が全く出てこなかったのが敗因でした。経験不足感がかなり出たのでn日1pwnのCrypto版でもやろうかなと思っています