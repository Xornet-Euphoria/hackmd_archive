---
tags: ctf
---

# TokyoWesterns CTF 6th 2020 Writeup

## Result

./Vespiaryで出て、32/648(スコアを入れたチーム)でした。日本の国旗を付けてる中だと2位でした。
私はWarmup~Easyぐらい(40Solvesぐらいまで)のRevとCryptoを解いたので今回はそのWriteupになります。

## Writeup

### easy-hash

問題のソースは次の通り

```python=
import struct
import os   

MSG = b'twctf: please give me the flag of 2020'

assert os.environ['FLAG']

def easy_hash(x):
    m = 0
    for i in range(len(x) - 3):
        m += struct.unpack('<I', x[i:i + 4])[0]
        m = m & 0xffffffff
    return m

def index(request):
    message = request.get_data()
    if message[0:7] != b'twctf: ' or message[-4:] != b'2020':
        return b'invalid message format: ' + message

    if message == MSG:
        return b'dont cheet'
    
    msg_hash = easy_hash(message)
    expected_hash = easy_hash(MSG)
    if msg_hash == expected_hash:
        return 'Congrats! The flag is ' + os.environ['FLAG']
    return 'Failed: easy_hash({}) is {}. but expected value is {}.'.format(message, msg_hash, expected_hash)

```

問題のサーバーにPOSTすると上記のような反応をする。`easy_hash`関数があり、先頭7文字が`b"twctf: "`、ケツ4文字が`b"2020"`であるようなメッセージの内、`easy_hash(b'twctf: please give me the flag of 2020')`とハッシュ値が同じになるものを探すという問題。

`easy_hash`だが、メッセージを4文字ずつ先頭からとりながらリトルエンディアンでアンパックしてその結果を足し合わせるという方法でハッシュ化している。

最初はハッシュ値が32bitなので適当に作ったメッセージをぶん回してれば大会期間中には終わるだろうと思い、見つかるまで試し続けるだけのスクリプトを書いて放置していた。
が、その待ち時間が暇だったので`easy_hash`を読んでいたら次のように桁毎に分割出来ることが分かった。

```
0  : t c w t
1  : f t c w
2  : : f t c
3  :   : f t
4  : ?   : f
5  : ? ?   :
...
n-1: 2 0 2 ?
  n: 0 2 0 2
-------------
   :h4h3h2h1
```

`?`は不明部分(バイト)である。これを0からnまで縦に足し、32bitの範囲に収まるようにしているのだが、各桁を見ていくと`twctf: ???...2020`の部分文字列を構成する文字のASCIIコードを全部足しているだけである。
例えば1番右の桁は`twctf: ... ?2`という文字列を構成する文字のASCIIコードの和を取っているし、右から3番目の桁(`h3`)は`ctf: ? ... ?02`という文字列を構成する文字のASCIIコードの和になっている。
いずれの桁も`prefix + unknown + suffix`というような形の文字列の文字のASCIIコードの和を取っており、`unknown`はどの桁でも足されている。
ということでこの`unknown`の値を適当に取り続け、桁ごとに足した値が、事前に計算しておいた目標のハッシュ値の各桁と一致するまで頑張ると`unknown = 2407`が出てくる。これに沿うような`unknown`のバイトを適当に考えて終わり、私は`"x"*13 + "y"*7`を使いました。

#### code

```python
import struct
from requests import post


MSG = b'twctf: please give me the flag of 2020'


def easy_hash(x):
    m = 0
    for i in range(len(x) - 3):
        packed = struct.unpack('<I', x[i:i + 4])[0]
        # print(hex(packed))
        m += packed
        m = m & 0xffffffff
    return m


def _easy_hash(x):
    h = 0
    l = len(x)
    for i in range(4):
        msg = x[i:l-3+i]
        h += (0x100**i) * sum(msg)

    return h & 0xffffffff


def upk(x):
    return struct.unpack("<I", x)[0]


if __name__ == '__main__':
    target = "https://crypto01.chal.ctf.westerns.tokyo"
    target_hash = easy_hash(MSG)

    assert target_hash == _easy_hash(MSG)
    print(hex(target_hash))

    prefix = b"twc"
    suffix = b"020"
    common = b"tf: 2"

    c = 0
    found = False
    while not found:
        c += 1
        h = 0
        for i in range(4):
            pre = prefix[i:3]
            suf = suffix[len(suffix)-i:]
            h += sum(pre+common+suf) + c

            if h % 0x100 != (target_hash >> (i*8)) % 0x100:
                break

            if i == 3:
                print(c)
                found = True
            h = h // 0x100

    new_msg = b"twctf: " + b"x"*13 + b"y"*7 + b"2020"

    print(easy_hash(new_msg))

    res = post(target, new_msg)
    print(res.text)

```

#### Flag

`TWCTF{colorfully_decorated_dream}`

### twin-d

問題のソースは次の通り

```python=
require 'json'
require 'openssl'

p = OpenSSL::BN::generate_prime(1024).to_i
q = OpenSSL::BN::generate_prime(1024).to_i

while true
    d = OpenSSL::BN::generate_prime(1024).to_i
    break if ((p - 1) * (q - 1)).gcd(d) == 1 && ((p - 1) * (q - 1)).gcd(d + 2) == 1
end

e1 = OpenSSL::BN.new(d).mod_inverse(OpenSSL::BN.new((p - 1) * (q - 1))).to_i
e2 = OpenSSL::BN.new(d + 2).mod_inverse(OpenSSL::BN.new((p - 1) * (q - 1))).to_i

flag = File.read('flag.txt')
msg = OpenSSL::BN.new(flag.unpack1("H*").to_i(16))
n = OpenSSL::BN.new(p * q)
enc = msg.mod_exp(OpenSSL::BN.new(e1), n)

puts ({ n: (p*q).to_s, e1: e1.to_s, e2: e2.to_s, enc: enc.to_s }).to_json

```

RSAっぽいが、公開鍵`N`の次に秘密鍵`d`(素数)を用意して`d, d+2`に対して公開鍵`e1, e2`を生成するという実装になっている。問題では暗号文に加えて`N, e1, e2`をくれるので「共通法攻撃でワンパンでは?」と思ったが暗号文は`pow(m, e1, N)`しかくれないので`pow(m, e2, N)`を導出することを目標にする。

とりあえず現状分かっているのは次の関係である。

$$
e_1d \equiv 1 \mod \phi(N) \\
e_2(d+2) \equiv 1 \mod \phi(N)
$$

これら2式の差を取って $d$ でくくると

$$
(e_1 - e_2)d - 2e_2 \equiv 0 \mod \phi(N)
$$

になる。とりあえず未知である`d`が邪魔なのでこれを消すために両辺 $e_1$ をかけて整理すると

$$
e_1 - e_2 \equiv 2e_1e_2 \mod \phi(N)
$$

になる。これで $\phi(N)$ を法とするそこそこ使えそうな合同式が手に入ったので $N$ を法とする合同式の指数に適用する。すると次のようになる。

$$
m^{e_1-e_2} \equiv m^{2e_1e_2} \mod N
$$

ここで $e_1$ で暗号化した暗号文 $c := m^{e_1} \mod N$ を定義すると

$$
C m^{-e_2} \equiv C^{2e_2} \mod N
$$

になるので

$$
m^{e_2} \equiv C C^{-2e_2} \mod N
$$

で $m^{e_2} \mod N$ を導出出来る事になり、共通法攻撃が適用できる。

#### Code

```python=
from xcrypto import ext_euclid, num_to_str


def common_modulous_attack(c1, c2, e1, e2, n):
    s1, s2, g = ext_euclid(e1, e2)
    _c1 = pow(c1, s1, n)
    _c2 = pow(c2, s2, n)

    return _c1 * _c2 % n


if __name__ == '__main__':
    n = 26524843197458127443771133945229625523754949369487014791599807627467226519111599787153382777120140612738257288082433176299499326592447109018282964262146097640978728687735075346441171264146957020277385391199481846763287915008056667746576399729177879290302450987806685085618443327429255304452228199990620148364422757098951306559334815707120477401429317136913170569164607984049390008219435634838332608692894777468452421086790570305857094650986635845598625452629832435775350210325954240744747531362581445612743502972321327204242178398155653455971801057422863549217930378414742792722104721392516098829240589964116113253433
    e1 = 3288342258818750594497789899280507988608009422632301901890863784763217616490701057613228052043090509927547686042501854377982072935093691324981837282735741669355268200192971934847782966333731663681875702538275775308496023428187962287009210326890218776373213535570853144732649365499644400757341574136352057674421661851071361132160580465606353235714126225246121979148071634839325793257419779891687075215244608092289326285092057290933330050466351755345025419017436852718353794641136454223794422184912845557812856838827270018279670751739019476000437382608054677808858153944204833144150494295177481906551158333784518167127
    e2 = 20586777123945902753490294897129768995688830255152547498458791228840609956344138109339907853963357359541404633422300744201016345576195555604505930482179414108021094847896856094422857747050686108352530347664803839802347635174893144994932647157839626260092064101372096750666679214484068961156588820385019879979501182685765627312099064118600537936317964839371569513285434610671748047822599856396277714859626710571781608350664514470335146001120348208741966215074474578729244549563565178792603028804198318917007000826819363089407804185394528341886863297204719881851691620496202698379571497376834290321022681400643083508905
    c = 18719581313246346528221007858250620803088488607301313701590826442983941607809029805859628525891876064099979252513624998960822412974893002313208591462294684272954861105670518560956910898293761859372361017063600846481279095019009757152999533708737044666388054242961589273716178835651726686400826461459109341300219348927332096859088013848939302909121485953178179602997183289130409653008932258951903333059085283520324025705948839786487207249399025027249604682539137261225462015608695527914414053262360726764369412756336163681981689249905722741130346915738453436534240104046172205962351316149136700091558138836774987886046

    c2 = pow(c, -2*e2, n) * c % n

    m = common_modulous_attack(c, c2, e1, e2, n)

    print(num_to_str(m))
```

#### Flag

`TWCTF{even_if_it_is_f4+e}`

### Tamarin

apkを渡されるのでいつもどおりunzipしてdex2jarにかけて...とするがそれで吸い出されるjarからは何も面白い情報は得られなかった。
問題名やjarで定義されているクラス等から察するにXamarinを使って作られたアプリっぽいのでググり力を駆使するとapkのunzip時に出現する`lib/libmonodroid_bundle_app.so`にC#で書いたコードがAndroidでも使えるような形で格納されるらしい。更にこれはdllにバラす事が出来ることが出来るらしいのでそのためのツールをCloneして来て使う。使ったのは[こちら](https://github.com/tjg1/mono_unbundle)。
ここで手に入るdll群の内、`Tamarin.dll`というのが実際に書かれたコードの本体っぽいのでdnSpyに食わせるといい感じにデコンパイルされる。

あとは読むだけ、気合でリバーシングするとだいたい次のような動作を行っている。

1. フラグの入力を促し、長さが4の倍数になるよう0(バイト)でパディングする
2. この入力を4バイトずつ取っていき、リトルエンディアンで数値に変換する。
3. `equation_array`という`uint`のリストのリストのような2次元配列が用意されており、この1次元目の要素`l[i]`に対し、`l[i] = [nums[i]] + l[i]`という形で先頭に要素を挿入する。但し、`nums`は先程手に入れたフラグを4文字毎に区切って数値に変換したものを順に並べた配列である。
4. これで更新された配列を方程式とみなす。具体的には`l[i][j]`は`j`が末尾でない(`l != len(l[i])`)の時に`j`次の係数となる。これで`len(l[i])-1`次の多項式を得る`j`が末尾、つまり`l[i][len(l[i])]`は先程得た多項式に変数を代入した時の比較対象となる。以下ではここで得られた多項式を $f_i(x)$ とおき、比較対象を $c_i$ とおく。よって各要素は $f_i(x) = c_i$ という方程式に対応することになる。なお、型が`uint`なので $2^{32}$ の剰余を取っている。
5. が、これを"計算する"わけではなく実際は $f_i^{10000}(x) = c_i$ が"成り立つ"かを調べられる。この時の最初に代入される変数 $x$ は乱数で生成される。一見すると無理そうに見えるが、実は $f_i(x)$ の係数はユーザーの入力に寄与しない、つまり元から`equation_array`でハードコーディングされている部分に関しては全てLSBが0、つまり偶数であり、偶奇性は0次係数であるユーザーの入力に依存する。
6. 手元でPythonで実装を再現し実験するとどうやらこの0次係数に依存する収束性もあることがわかった。これは最初に代入する変数が何であっても収束先は同じになる。
7. 更に0次係数の、あるバイトより下のバイトが同じなら上のバイトが何であってもそのバイト部分の収束先は同じであるという事もわかった(おそらくbitでも同じことが言える)。厳密な証明はしていないが、これらの性質が成り立つと仮定して各方程式が成り立つよう0次係数をバイトごと、総当たりで求めれば良い。

#### code

```python=
from pwn import p32
from string import printable
from num_list import num_list


# pow(x, n)
def func1(x, n):
    num = 1
    for i in range(n):
        num *= x

    return num % 0x100000000


def func2(cs, x, pos):
    if pos == -1:
        return 0

    num = cs[pos] * func1(x, pos)
    return (num + func2(cs, x, pos - 1)) % 0x100000000


def calc_final_hash(l):
    res = 0xdeadbeef
    for i in range(50):
        res = func2(l, res, len(l)-2)
        # print(hex(res))

    return res


def crack(l):
    table = printable[:-6]
    ret = 0
    for i in range(4):
        target = l[-1] & (0x100**(i+1)-1)
        for c in table:
            c_n = ord(c) * (0x100**i)
            ret += c_n
            _l = [ret] + l
            res = calc_final_hash(_l)
            if res & (0x100**(i+1)-1) == target:
                print("found")
                break
            ret -= c_n

    return ret


if __name__ == '__main__':
    flag = b""

    for l in num_list:
        flag += p32(crack(l))

    print(flag)

```

#### Flag

`TWCTF{Xm4r1n_15_4bl3_70_6en3r4t3_N471v3_C0d3_w17h_VS_3n73rpr153_bu7_17_c0n741n5_D07_N3t_B1n4ry}`

## 感想

面白かったです。先週のCSAW CTFのCryptoが微妙で不完全燃焼でしたが、TWCTFのCryptoは楽しめました。特にtwin-dが好きでした。こういう式変形RSAは大好物です。

本番は開幕24時間で上記の問題を解いてから残り何も出来ず幼児退行寸前になっていましたが、粘り強く取り組む事は出来たと思います。そこまで熱中出来るぐらいには良い問題が多かったです。

昨年に引き続き楽しいCTFを提供してくださったTokyoWesternsの皆様、ありがとうございました。来年も参加します。