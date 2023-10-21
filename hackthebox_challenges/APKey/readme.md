# APKey

> This app contains some unique keys. Can you get one?

[APKey.zip](./APKey.zip), with zip password `hackthebox` and sha256sum
`0e901ee8858a83d64bf65daead62785c89ac157440b8c1affbc62b32036cccf1` which expands
to:

```
./APKey
└── APKey.apk
```

decompiling the apk can simply be done via `jadx-gui (jadx)`

```shell
$ jadx-gui $PWD/APKey.apk
```

this gives the android main activity, which contains:

```java
        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            Toast makeText;
            String str;
            try {
                if (MainActivity.this.f928c.getText().toString().equals("admin")) {
                    MainActivity mainActivity = MainActivity.this;
                    b bVar = mainActivity.e;
                    String obj = mainActivity.d.getText().toString();
                    try {
                        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                        messageDigest.update(obj.getBytes());
                        byte[] digest = messageDigest.digest();
                        StringBuffer stringBuffer = new StringBuffer();
                        for (byte b2 : digest) {
                            stringBuffer.append(Integer.toHexString(b2 & 255));
                        }
                        str = stringBuffer.toString();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                        str = "";
                    }
                    if (str.equals("a2a3d412e92d896134d9c9126d756f")) {
                        Context applicationContext = MainActivity.this.getApplicationContext();
                        MainActivity mainActivity2 = MainActivity.this;
                        b bVar2 = mainActivity2.e;
                        g gVar = mainActivity2.f;
                        makeText = Toast.makeText(applicationContext, b.a(g.a()), 1);
                        makeText.show();
                    }
                }
                makeText = Toast.makeText(MainActivity.this.getApplicationContext(), "Wrong Credentials!", 0);
                makeText.show();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }
```

this java code looks to take in a password and username from a user, checks if the username is `admin` and password
hashes to `a2a3d412e92d896134d9c9126d756f` via MD5, and the prints whatever `b.a(g.a())`

looking at the java code of the `g.a()` function in the package `c.b.a` gives:

```java
public class g {
    public static String a() {
        StringBuilder sb = new StringBuilder();
        ArrayList arrayList = new ArrayList();
        arrayList.add("722gFc");
        arrayList.add("n778Hk");
        arrayList.add("jvC5bH");
        arrayList.add("lSu6G6");
        arrayList.add("HG36Hj");
        arrayList.add("97y43E");
        arrayList.add("kjHf5d");
        arrayList.add("85tR5d");
        arrayList.add("1UlBm2");
        arrayList.add("kI94fD");
        sb.append((String) arrayList.get(8));
        sb.append(h.a());
        sb.append(i.a());
        sb.append(f.a());
        sb.append(e.a());
        ArrayList arrayList2 = new ArrayList();
        arrayList2.add("ue7888");
        arrayList2.add("6HxWkw");
        arrayList2.add("gGhy77");
        arrayList2.add("837gtG");
        arrayList2.add("HyTg67");
        arrayList2.add("GHR673");
        arrayList2.add("ftr56r");
        arrayList2.add("kikoi9");
        arrayList2.add("kdoO0o");
        arrayList2.add("2DabnR");
        sb.append((String) arrayList2.get(9));
        sb.append(c.a());
        ArrayList arrayList3 = new ArrayList();
        arrayList3.add("jH67k8");
        arrayList3.add("8Huk89");
        arrayList3.add("fr5GtE");
        arrayList3.add("Hg5f6Y");
        arrayList3.add("o0J8G5");
        arrayList3.add("Wod2bk");
        arrayList3.add("Yuu7Y5");
        arrayList3.add("kI9ko0");
        arrayList3.add("dS4Er5");
        arrayList3.add("h93Fr5");
        sb.append((String) arrayList3.get(5));
        sb.append(d.a());
        sb.append(a.a());
        return sb.toString();
    }

    public static String b() {
        char charAt = d.a().charAt(1);
        char charAt2 = i.a().charAt(2);
        char charAt3 = i.a().charAt(1);
        return String.valueOf(charAt) + String.valueOf(charAt2) + String.valueOf(charAt3);
    }
}
```

looking at java code of the `b.a(...)` function in the package `c.b.a` gives the following

```java
package c.b.a;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: classes.dex */
public class b {
    public static String a(String str) {
        char charAt = h.a().charAt(0);
        char charAt2 = a.a().charAt(8);
        char charAt3 = e.a().charAt(5);
        char charAt4 = i.a().charAt(4);
        char charAt5 = h.a().charAt(1);
        char charAt6 = h.a().charAt(4);
        char charAt7 = h.a().charAt(3);
        char charAt8 = h.a().charAt(3);
        char charAt9 = h.a().charAt(0);
        char charAt10 = a.a().charAt(8);
        char charAt11 = a.a().charAt(8);
        char charAt12 = i.a().charAt(0);
        char charAt13 = c.a().charAt(3);
        char charAt14 = f.a().charAt(3);
        char charAt15 = f.a().charAt(0);
        char charAt16 = c.a().charAt(0);
        SecretKeySpec secretKeySpec = new SecretKeySpec((
              String.valueOf(charAt) +
              String.valueOf(charAt2) +
              String.valueOf(charAt3) +
              String.valueOf(charAt4) +
              String.valueOf(charAt5).toLowerCase() +
              String.valueOf(charAt6) +
              String.valueOf(charAt7).toLowerCase() +
              String.valueOf(charAt8) +
              String.valueOf(charAt9) +
              String.valueOf(charAt10).toLowerCase() +
              String.valueOf(charAt11).toLowerCase() +
              String.valueOf(charAt12) +
              String.valueOf(charAt13).toLowerCase() +
              String.valueOf(charAt14) +
              String.valueOf(charAt15) +
              String.valueOf(charAt16)).getBytes(), g.b());
        Cipher cipher = Cipher.getInstance(g.b());
        cipher.init(2, secretKeySpec);
        return new String(cipher.doFinal(Base64.decode(str, 0)), "utf-8");
    }
}
```

these functions, along with other child calls can be emulated within Python3

```python3
#!/usr/bin/env python3

from base64 import b64decode

def h_a():
    return "kHtZuV"

def i_a():
    return "rSE6qY"

def f_a():
    return "6HxWkw"

def e_a():
    return "HyeaX9"

def c_a():
    return "FlEGyL"

def d_a():
    return "wAxcoc"

def a_a():
    return "85S94kFpV1"

def g_a():
    return ''.join([
            "1UlBm2",
            h_a(),
            i_a(),
            f_a(),
            e_a(),
            "2DabnR",
            c_a(),
            "Wod2bk",
            d_a(),
            a_a(),
        ])

def g_b():
    return ''.join([
        d_a()[1],
        i_a()[2],
        i_a()[1],
    ])

def main():
    b_str = bytes(''.join([
        h_a()[0],
        a_a()[8],
        e_a()[5],
        i_a()[4],
        h_a()[1].lower(),
        h_a()[4],
        h_a()[3].lower(),
        h_a()[3],
        h_a()[0],
        a_a()[8].lower(),
        a_a()[8].lower(),
        i_a()[0],
        c_a()[3].lower(),
        f_a()[3],
        f_a()[0],
        c_a()[0],
    ]), "utf-8")

    print("key:", b_str, "method:", g_b(), "message:", g_a())

    return

if __name__ == "__main__":
    main()
```

this gives that the algorithm is `AES` and the key (in base64) is `kV9qhuzZkvvrgW6F`.

now, creating a java program (or using [onecompiler](https://onecomipler.com/java/)) allows us to decrypt the flag!

```java
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Main {
    public static void main(String[] args) {
      String enc = "1UlBm2kHtZuVrSE6qY6HxWkwHyeaX92DabnRFlEGyLWod2bkwAxcoc85S94kFpV1";
      String key = "kV9qhuzZkvvrgW6F";
      String method = "AES";
      try{
        SecretKeySpec sks = new SecretKeySpec(key.getBytes(), method);
        Cipher cipher = Cipher.getInstance(method);
        cipher.init(2, sks);
        
        System.out.println(new String(cipher.doFinal(Base64.getDecoder().decode(enc)), "utf-8"));
      } catch(Exception e) {
        System.err.println("bad :(");
        System.err.println(e);
      }
  }
}
```

flag: `HTB{m0r3_0bfusc4t1on_w0uld_n0t_hurt}`
