---
tags: crypto, ctf
---

# Crypto CTF 2020 - Three Ravens

* 会場: <https://cryp.toc.tf/>
* これまでに解いた問題: https://hackmd.io/@Xornet/BkemeSAhU

## Writeup

### Outline

p, q, rが素数でかつ、この3つの和も素数であるものが用意され、この4つの積を公開鍵としてe=0x10001でRSA暗号を用いて暗号化している。但し、公開鍵はp, q, rの積とp+q+rの2つが公開されている。
この方式の法Nはp+q+rが素因数でしかも公開されているのでp+q+rを法とした暗号化とみなせば簡単に復号出来る。平文がp+q+rより小さい事を期待してこの場合の秘密鍵を求めて復号すると無事にフラグが表示された。

### 問題のコード

```python=
#!/usr/bin/python

from Crypto.Util.number import *
from flag import flag

def keygen(nbit):
	while True:
		p, q, r = [getPrime(nbit) for _ in range(3)]
		if isPrime(p + q + r):
			pubkey = (p * q * r, p + q + r)
			privkey = (p, q, r)
			return pubkey, privkey

def encrypt(msg, pubkey):
	enc = pow(bytes_to_long(msg.encode('utf-8')), 0x10001, pubkey[0] * pubkey[1])
	return enc

nbit = 512
pubkey, _ = keygen(nbit)
print('pubkey =', pubkey)

enc = encrypt(flag, pubkey)
print('enc =', enc)

```

512bitの素数`p.q.r`を3つ用意し`p*q*r, p+q+r`を公開鍵としている。法`N`は`N = p*q*r*(p+q+r)`である。また、`p+q+r`は素数である。

### 法を変える

以下フラグを $m$、暗号文`enc`を $c$ とし、 $\alpha := pqr, \beta := p+q+r$ と定義する。この時

$$
m^e \equiv c \mod N
$$

であることから

$$
m^e = k \times pqr\beta + c
$$

となる整数 $k$ が存在する。これを変形すると

$$
m^e \equiv c \mod \beta
$$

であることから法を $\beta$ とみなした時の秘密鍵を求めることが出来れば、フラグを復号出来そうである(但し、フラグが $\beta$ より小さいという制約がある)。

### 秘密鍵を導出する

$\beta$ は既知である上に素数なのでこの場合の秘密鍵は簡単に求めることが出来る。フェルマーの小定理から単純に $ed + k(\beta - 1) = 1$ となるような $d$ を求めれば良く、これは拡張Euclid互除法で出来る(なお $k$ は何らかの整数)。
求まったらあとは $c^d \mod \beta$ を求めて文字にすると無事にフラグが表示された。

## Code

```python=
from xcrypto import *


if __name__ == '__main__':
    pubkey = (1118073551150541760383506765868334289095849217207383428775992128374826037924363098550311115755885268424829560194236035782255428423619054826556807583363177501160213010458887123857150164238253637312857212126083296001975671629067724687807682085295986049189947830021121209617616433866087257702543240938795900959368763108186758449391390546819577861156371516299606594152091361928029030465815445679749601118940372981318726596366101388122993777320367839724909505255914071,
              31678428119854378475039974072165136708037257624045332601158556362844808093636775192373992510841508137996049429030654845564354209680913299308777477807442821)
    enc = 8218052282226011897229703907763521214054254785275511886476861328067117492183790700782505297513098158712472588720489709882417825444704582655690684754154241671286925464578318013917918101067812646322286246947457171618728341255012035871158497984838460855373774074443992317662217415756100649174050915168424995132578902663081333332801110559150194633626102240977726402690504746072115659275869737559251377608054255462124427296423897051386235407536790844019875359350402011464166599355173568372087784974017638074052120442860329810932290582796092736141970287892079554841717950791910180281001178448060567492540466675577782909214

    e = 0x10001
    alpha, beta = pubkey
    n = alpha*beta

    d, k, g = ext_euclid(e, beta - 1)
    _enc = enc % beta
    print(num_to_str(pow(_enc, d, beta)))
```

## Flag

`CCTF{tH3_thr3E_r4V3n5_ThRe3_cR0w5}`

## 感想

和の3乗等の式変形をゴリゴリやって`p*q*r`との共通因数を見つける問題かと思いきや、気が付けば早いタイプの問題でした。
最初、`p+q+r`を法とせず、`N`を法と復号していていつまでもフラグが現れないと発狂してましたが、なんとか気づけてよかったです