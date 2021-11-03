---
tags: crypto, ctf
---

# InterKosenCTF 2020 - ochazuke

* 作問者Writeup: <https://hackmd.io/@theoldmoon0602/r1Wcuq77v>
* 作問者感想: <https://yoshiking.hatenablog.jp/entry/2020/09/07/101829>
* CTFのリポジトリ: <https://github.com/theoremoon/InterKosenCTF2020-challenges>
* これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

楕円曲線DSA(以下、ECDSA)の問題。`"ochazuke`以外の任意のメッセージを署名し、その結果をくれる。その後、署名を与えるとそれを検証しメッセージが`"ochazuke"`であればフラグを表示する。
ECDSAでは署名時に使われるパラメータ`k`を使い回すと2つの異なるメッセージに対する署名から`k`が判明し、更にそこから秘密鍵を割り出すことが可能であるという性質がある。
今回この`k`は与えたメッセージのSHA-1ハッシュに依存する。ということはGoogleが提示した例の2つのpdfの上部のバイトをメッセージとして送れば異なるメッセージで同じ`k`という状況に持ち込む事ができる。

後は`k`を計算してそこから秘密鍵を割り出し、`"ochazuke"`の署名を生成して送り出せばフラグが手に入る

### SHA-1の衝突

詳しくは参考文献1に書かれているのでそちらに全部投げるが、数年前にGoogleはSHA-1の強衝突耐性を破る事に成功し、異なるファイルにも関わらずSHA-1にかけた際のハッシュ値が同じである2つのpdfを公開した。
これは実は先頭の数百バイトが違うだけで残りは同じであることから、先頭の数百バイト以後が同じバイトならどのようなバイト列であっても衝突する。
このpdfを丸ごと送っても良いのだが、データがデカ過ぎて怒られると嫌だったのでとりあえず衝突してかつ最も短いものを用意した。

ちなみに例の2つのpdfは参考文献2から拝借できる。

### 秘密鍵導出

参考文献3に書かれていることのコピペになってしまうので深くは立ち入らないが(そっちを読んでください)、ECDSAでは使い回してはいけないパラメータがある。これは署名で使われる楕円曲線上の点の指数`k`になるのだが、今回の問題では次のように定義されている(ソースコード中の`k`(小文字))。

```python=
def sign(private_key, message):
    z = Zn(bytes_to_long(message))
    k = Zn(ZZ(sha1(message).hexdigest(), 16)) * private_key
    assert k != 0
    K = ZZ(k) * G
    r = Zn(K[0])
    assert r != 0
    s = (z + r * private_key) / k
    assert s != 0
    return (r, s)
```

本来この`k`はランダムに取って来るのでセッションごとに異なるはずなのだが、今回は平文のSHA-1ハッシュ値と秘密鍵に依存している。
秘密鍵は毎回固定(サーバー側のコードで`from secret import flag, d`していることによる推測)なので`k`は平文のSHA-1ハッシュ値に依存する。ということは上で述べたSHA-1の衝突方法で衝突ペアを生成して平文として送れば毎回同じ`k`が使われることになる。

`sign`の定義を見ると`s = (z + r * private_key) / k`である。ということは2つのメッセージ(の数値表現) $z1, z2$ に対して

$$
s_1 = (z_1 + r * priv\_key) k^{-1} \\
s_2 = (z_2 + r * priv\_key) k^{-1}
$$

が成り立つ。上式から下式を引くと

$$
s_1 - s_2 = (z_1 - z_2) k^{-1}
$$

となり、これを整理すると

$$
k = (z_1 - z_2) (s_1 - s_2)^{-1}
$$

となる。この署名では`r, s`が与えられ、`z`は平文から判明することからこの計算によって`k`を導出出来る。

あらためてソースコード中の`s`の定義を見ると`s, z, r, k`は判明したので秘密鍵を次のように逆算することが出来る。

$$
priv\_key = (sk - z) r^{-1}
$$

そういえば、このWriteupを書いていて気付いたが、秘密鍵は`k`の定義から平文と`k`だけで求めることが出来そうである。
今回は参考文献3にしたがって`k`と片方の署名から愚直に計算した。

### 署名の偽装

秘密鍵を導出出来たのでこれで`"ochazuke"`の署名を手元で生成することが出来る。私のSage環境は貧弱なので`bytes_to_long`を自前で実装したが、他は実際にサーバー側で使われているモノと全く同じである。
こうして偽装した署名を送り、`"ochazuke"`と認証されればフラグが開示される。
偽装した署名送信のタイミングはこちらで署名したいメッセージを送った後なので秘密鍵をリークするコードをそのまま流用した。

## Code

### 秘密鍵のリークと署名の送信(python)

```python=
from Crypto.Util.number import bytes_to_long
from hashlib import sha1, md5
from binascii import unhexlify, hexlify
from pwn import remote
from xcrypto import *
from xlog import XLog

logger = XLog()


def send_msg(s, msg):
    s.recvuntil(b"(hex): ")
    s.sendline(msg)
    s.recvuntil(b"signature: ")
    res = tuple(map(int, s.recvline().rstrip()[1:-1].split(b", ")))

    return res


if __name__ == '__main__':
    target = "crypto.kosenctf.com"
    port = 13005
    n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

    m_1 = b""
    with open("./shattered-1.pdf", "rb") as f:
        m_1 = f.read()

    m_2 = b""
    with open("./shattered-2.pdf", "rb") as f:
        m_2 = f.read()

    i = 193
    while True:
        sub_m_1 = m_1[0:i]
        sub_m_2 = m_2[0:i]
        hash_1 = sha1(sub_m_1).hexdigest()
        hash_2 = sha1(sub_m_2).hexdigest()
        if hash_1 == hash_2:
            hash_md5_1 = md5(sub_m_1).hexdigest()
            hash_md5_2 = md5(sub_m_2).hexdigest()
            assert hash_md5_1 != hash_md5_2
            logger.info(f"shattered!! {i}")
            break
        i += 1

    hexed_1 = hexlify(sub_m_1)
    hexed_2 = hexlify(sub_m_2)

    assert hexed_1 != hexed_2

    s = remote(target, port)
    sign_1 = send_msg(s, hexed_1)
    print(sign_1)
    s.close()

    s = remote(target, port)
    sign_2 = send_msg(s, hexed_2)
    print(sign_2)

    assert sign_1[0] == sign_2[0]
    r = sign_1[0]

    z_1 = bytes_to_long(sub_m_1)
    z_2 = bytes_to_long(sub_m_2)

    k = (z_1 - z_2) * pow((sign_1[1]) - sign_2[1], -1, n) % n

    d = (sign_1[1] * k - z_1) * pow(r, -1, n) % n
    _d = (sign_2[1] * k - z_2) * pow(r, -1, n) % n

    assert d == _d

    logger.info(f"secret is leaked -> {d}")

    # from sagemath
    ochazuke_sig = (98165594340872803797719590291390519389514915039788511532783877037454671871717, 115665584943357876566217145953115265124053121527908701836053048195862894185539)

    s.recvuntil(b"ochazuke's signature: ")
    s.sendline(str(ochazuke_sig))

    print(s.recv(4096))
```

### 署名の生成(SageMath)

```python=
from binascii import unhexlify, hexlify
from hashlib import sha1

EC = EllipticCurve(
    GF(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff),
    [-3, 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b]
)

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 # EC.order()
Zn = Zmod(n)
G = EC((0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5))
        
def bytes_to_long(b):
    hexed = hexlify(b)
    return int(hexed, 16)


def sign(private_key, message):
    z = Zn(bytes_to_long(message))
    k = Zn(ZZ(sha1(message).hexdigest(), 16)) * private_key
    assert k != 0
    K = ZZ(k) * G
    r = Zn(K[0])
    assert r != 0
    s = (z + r * private_key) / k
    assert s != 0
    return (r, s)
    
# from python script
d = 313681195146870630150443675574660225833

print(sign(d, b"ochazuke"))
```

## Flag

当日は別のチームメイトが解き、この手法を思いついて提案した直後に別解で通してたので使われませんでしたが、鯖がまだ動いていたので供養の為に解きました

`KosenCTF{ahhhh_ochazuke_oisi_geho!geho!!gehun!..oisii...}`

## 感想

初めての楕円曲線絡みの問題で面白かったです。また、単純な暗号解読ではなく、署名に関する問題というのも久しぶりで面白かったです。
本質は(nを法とする演算だけで出来る)秘密鍵の導出にあるので、楕円曲線という威圧感の割に特に複雑な数学が要求されなかったことも良かったです。

見た当時は「うっ...何も勉強してないし経験も無い楕円曲線だ...」となって取り組んでませんでした。
実はこの問題がチームで提出してなかった最後の問題であり、まあここまでやったし良いだろうとかほざいてたらチームメイトに「去年も1残しだったのにそれでいいのか"Crypto担当さん"」と煽られたのでECDSAのWikipediaを読むだけの役をしていました。
結果として異なる平文で`k`が同じになる状況をGoogleの例のpdfで出来るんじゃね?と言った数分後に別のチームメイトが非想定解(作問者感想を参照)で解いていたので私は全く貢献できませんでしたが、終了後にこうやって復習出来たので良かったです。

これを期に楕円曲線暗号に関しては真面目に勉強しようと思います。6月に似たようなきっかけでHeapの勉強も出来て本番で解けるようになったので同じ感じでやっていきたいです。
あと、今までやったことがないとの理由で諦めるのは今振り返ると見苦しい言い訳なのでかなり反省しています。ここ最近、「残り時間も短いし復習でやればいいや」という思考が先行しがちなのでこいつを直したいです。

## 参考文献

1. GoogleのSHA-1のはなし - slideshare: <https://www.slideshare.net/herumi/googlesha1>
2. SHAttered: <https://shattered.io/>
3. 楕円曲線DSA - Wikipedia: <https://ja.wikipedia.org/wiki/%E6%A5%95%E5%86%86%E6%9B%B2%E7%B7%9ADSA>