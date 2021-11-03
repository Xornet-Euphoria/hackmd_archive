---
tags: ctf
---

# SECCON Beginners CTF 2020 - siblangs

## Writeup

### outline

apkの解析をする問題。フラグのvalidate部分は2つ存在し、1つはReactで書かれ、もう1つは普通にjavaで書かれている。
前者は難読化されており、非常に読みづらいが適当な難読化解除ツールに掛けてフラグに関与している部分を読めば簡単にフラグを復元できる。
後者はAESで暗号化されたフラグの一部の復号結果が入力と一致するかを確認している。鍵もIVも暗号文もわかるが、単純に入力とフラグの一部が等しいかを照合している部分があるので、その際の比較対象をそのまま出力すればフラグの一部が手に入る

あとは2つを繋げて終わり

### apk解析パート

apkの実態はzipなのでunzipすると諸々が見れる。とりあえず欲しいのは`.dex`拡張子を持つファイルで、これはjar形式へと変換出来ることから変換する。変換にはdex2jarというツールを用いた(参考文献に載せた)

```
$ ~/dextools/d2j-dex2jar.sh classes.dex
dex2jar classes.dex -> ./classes-dex2jar.jar
```

jarファイルは適当なデコンパイラに投げるとデコンパイルしてくれるのだが、今回はJD-GUIを使用した。
ここから`es.o0i.challenge.app/nativemodule/ValidateFlagModule.class`を読むとそれっぽい処理をしているのでここを読んでみる

### javaのソースコード解析パート

`ValidateFlagModule.class`は次のようになっている

```java=
package es.o0i.challengeapp.nativemodule;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ValidateFlagModule extends ReactContextBaseJavaModule {
  private static final int GCM_IV_LENGTH = 12;
  
  private final ReactApplicationContext reactContext;
  
  private final SecretKey secretKey = new SecretKeySpec("IncrediblySecure".getBytes(), 0, 16, "AES");
  
  private final SecureRandom secureRandom = new SecureRandom();
  
  public ValidateFlagModule(ReactApplicationContext paramReactApplicationContext) {
    super(paramReactApplicationContext);
    this.reactContext = paramReactApplicationContext;
  }
  
  public String getName() {
    return "ValidateFlagModule";
  }
  
  @ReactMethod
  public void validate(String paramString, Callback paramCallback) {
    byte[] arrayOfByte = new byte[43];
    arrayOfByte[0] = 95;
    arrayOfByte[1] = -59;
    arrayOfByte[2] = -20;
    arrayOfByte[3] = -93;
    arrayOfByte[4] = -70;
    arrayOfByte[5] = 0;
    arrayOfByte[6] = -32;
    arrayOfByte[7] = -93;
    arrayOfByte[8] = -23;
    arrayOfByte[9] = 63;
    arrayOfByte[10] = -9;
    arrayOfByte[11] = 60;
    arrayOfByte[12] = 86;
    arrayOfByte[13] = 123;
    arrayOfByte[14] = -61;
    arrayOfByte[15] = -8;
    arrayOfByte[16] = 17;
    arrayOfByte[17] = -113;
    arrayOfByte[18] = -106;
    arrayOfByte[19] = 28;
    arrayOfByte[20] = 99;
    arrayOfByte[21] = -72;
    arrayOfByte[22] = -3;
    arrayOfByte[23] = 1;
    arrayOfByte[24] = -41;
    arrayOfByte[25] = -123;
    arrayOfByte[26] = 17;
    arrayOfByte[27] = 93;
    arrayOfByte[28] = -36;
    arrayOfByte[29] = 45;
    arrayOfByte[30] = 18;
    arrayOfByte[31] = 71;
    arrayOfByte[32] = 61;
    arrayOfByte[33] = 70;
    arrayOfByte[34] = -117;
    arrayOfByte[35] = -55;
    arrayOfByte[36] = 107;
    arrayOfByte[37] = -75;
    arrayOfByte[38] = -89;
    arrayOfByte[39] = 3;
    arrayOfByte[40] = 94;
    arrayOfByte[41] = -71;
    arrayOfByte[42] = 30;
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec gCMParameterSpec = new GCMParameterSpec();
      this(128, arrayOfByte, 0, 12);
      cipher.init(2, this.secretKey, gCMParameterSpec);
      arrayOfByte = cipher.doFinal(arrayOfByte, 12, arrayOfByte.length - 12);
      byte[] arrayOfByte1 = paramString.getBytes();
      for (byte b = 0; b < arrayOfByte.length; b++) {
        if (arrayOfByte1[b + 22] != arrayOfByte[b]) {
          paramCallback.invoke(new Object[] { Boolean.valueOf(false) });
          return;
        } 
      } 
      paramCallback.invoke(new Object[] { Boolean.valueOf(true) });
    } catch (Exception exception) {
      paramCallback.invoke(new Object[] { Boolean.valueOf(false) });
    } 
  }
}
```

`"IncrediblySecure".getBytes()`を鍵としてAESで暗号化/復号をしているようである。ivや暗号文も判明するのだが82行目の`arrayOfByte`と入力を比べているだけなので`arrayOfByte`の中身を出力すればフラグが判明しそうである。
というわけでそういう風に書き換えて普通にjavaが動く環境実行したらフラグの一部が出た。

flag(latter half): `1pt_3verywhere}`

### JS解析パート

さて、もう1つはどこを探しても上手く出てこなかったので`ctf4b`で検索をかけたところunzipした時に出てきた`assets/index.android.bundle`が引っ掛かった。
問題はこれが難読化されているためひとまず読みやすい形に整形する。適当なWebサイトにやらせた。

すると次のような関数がヒットする

```javascript=
function v() {
    var t;
    (0, l.default)(this, v);
    for (var o = arguments.length, n = new Array(o), c = 0; c < o; c++) n[c] = arguments[c];
    return (t = y.call.apply(y, [this].concat(n))).state = {
        flagVal: "ctf4b{",
        xored: [34, 63, 3, 77, 36, 20, 24, 8, 25, 71, 110, 81, 64, 87, 30, 33, 81, 15, 39, 90, 17, 27]
    }, t.handleFlagChange = function (o) {
        t.setState({
            flagVal: o
        })
    }, t.onPressValidateFirstHalf = function () {
        if ("ios" === h.Platform.OS) {
            for (var o = "AKeyFor" + h.Platform.OS + "10.3", l = t.state.flagVal, n = 0; n < t.state.xored.length; n++)
                if (t.state.xored[n] !== parseInt(l.charCodeAt(n) ^ o.charCodeAt(n % o.length), 10)) return void h.Alert.alert("Validation A Failed", "Try again...");
            h.Alert.alert("Validation A Succeeded", "Great! Have you checked the other one?")
        } else h.Alert.alert("Sorry!", "Run this app on iOS to validate! Or you can try the other one :)")
    }, t.onPressValidateLastHalf = function () {
        "android" === h.Platform.OS ? p.default.validate(t.state.flagVal, function (t) {
            t ? h.Alert.alert("Validation B Succeeded", "Great! Have you checked the other one?") : h.Alert.alert("Validation B Failed", "Learn once, write anywhere ... anywhere?")
        }) : h.Alert.alert("Sorry!", "Run this app on Android to validate! Or you can try the other one :)")
    }, t
}
```

`alert`の中身とか見ているとおそらくここで入力のvalidateを行っているように見えるので読んでみると`"AKeyFor" + h.Platform.OS + "10.3"`を鍵として順次入力文字に対してxorしているように思える。その結果が`xored`と一致すれば良いのでこれを元にして正しい入力を復元するコードを書けば良い

flag(former half): `ctf4b{jav4_and_j4va5cr`

というわけでこれをくっつけたものがフラグになる

## code

### java解析パート

```java=
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    public static void main(String[] args) throws Exception {
        // Your code here!
        SecretKey secretKey = new SecretKeySpec("IncrediblySecure".getBytes(), 0, 16, "AES");
        byte[] arrayOfByte = new byte[43];
        arrayOfByte[0] = 95;
        arrayOfByte[1] = -59;
        arrayOfByte[2] = -20;
        arrayOfByte[3] = -93;
        arrayOfByte[4] = -70;
        arrayOfByte[5] = 0;
        arrayOfByte[6] = -32;
        arrayOfByte[7] = -93;
        arrayOfByte[8] = -23;
        arrayOfByte[9] = 63;
        arrayOfByte[10] = -9;
        arrayOfByte[11] = 60;
        arrayOfByte[12] = 86;
        arrayOfByte[13] = 123;
        arrayOfByte[14] = -61;
        arrayOfByte[15] = -8;
        arrayOfByte[16] = 17;
        arrayOfByte[17] = -113;
        arrayOfByte[18] = -106;
        arrayOfByte[19] = 28;
        arrayOfByte[20] = 99;
        arrayOfByte[21] = -72;
        arrayOfByte[22] = -3;
        arrayOfByte[23] = 1;
        arrayOfByte[24] = -41;
        arrayOfByte[25] = -123;
        arrayOfByte[26] = 17;
        arrayOfByte[27] = 93;
        arrayOfByte[28] = -36;
        arrayOfByte[29] = 45;
        arrayOfByte[30] = 18;
        arrayOfByte[31] = 71;
        arrayOfByte[32] = 61;
        arrayOfByte[33] = 70;
        arrayOfByte[34] = -117;
        arrayOfByte[35] = -55;
        arrayOfByte[36] = 107;
        arrayOfByte[37] = -75;
        arrayOfByte[38] = -89;
        arrayOfByte[39] = 3;
        arrayOfByte[40] = 94;
        arrayOfByte[41] = -71;
        arrayOfByte[42] = 30;
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gCMParameterSpec = new GCMParameterSpec(128, arrayOfByte, 0, 12);
        cipher.init(2, secretKey, gCMParameterSpec);
        arrayOfByte = cipher.doFinal(arrayOfByte, 12, arrayOfByte.length - 12);
        
        String flag;
        flag = new String(arrayOfByte, "US-ASCII");
        
        System.out.println(flag);
    }
}

```

### JS解析パート

```python=
if __name__ == '__main__':
    xored = [34, 63, 3, 77, 36, 20, 24, 8, 25, 71, 110, 81, 64, 87, 30, 33, 81, 15, 39, 90, 17, 27]

    key = "AKeyForios10.3"
    l = len(key)

    flag = ""
    for i, c in enumerate(xored):
        flag += chr(c ^ ord(key[i % l]))

    print(flag)
```

## Flag

`ctf4b{jav4_and_j4va5cr1pt_3verywhere}`

## 感想

この前にapk解析ツールをインストールすれば終わる程度の問題を解いてapk解析用の環境が整ったので応用の為に解きました。
初めてのapk問題で色々なツールやapkの構造を知れて面白かったです。

## 参考文献

* <https://github.com/pxb1988/dex2jar>: dexからjarを取り出すツール。Downloadsから落としてくるだけで使える。
* <http://java-decompiler.github.io/>: JD-GUIはここから落とした