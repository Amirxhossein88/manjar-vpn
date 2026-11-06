#!/bin/bash
# =============================================================
# ManjarVPN v1.8 — بیلدِ APK اندروید (بدون Gradle)
# پیش‌نیازها:
#   - JDK 17 (javac/jar/keytool در PATH یا متغیر JDK)
#   - Android SDK: build-tools;34.0.0 و platforms;android-34
#   - هسته‌ی Xray اندروید arm64 (از ریلیزهای رسمی XTLS/Xray-core)
#     → android/app/src/main/jniLibs/arm64-v8a/libxray.so
#   - hev-socks5-tunnel: classes.jar (از AAR) و libhev-socks5-tunnel.so
# خروجی: android/build/ManjarVPN-1.8.2-android.apk
# =============================================================
set -e

# ---- مسیرها (در صورت نیاز تغییر دهید) ----
JDK="${JDK:-$ANDROID_HOME/../jdk17}"          # یا مسیر JDK 17
SDK="${ANDROID_HOME:-$HOME/android-sdk}"
BT="$SDK/build-tools/34.0.0"
PLAT="$SDK/platforms/android-34/android.jar"

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/app/src/main"
OUT="$ROOT/build"
HEV_CLS="${HEV_CLS:-$ROOT/third-party/hev-classes.jar}"   # classes.jar از داخل hev AAR

rm -rf "$OUT"
mkdir -p "$OUT/gen" "$OUT/classes" "$OUT/dex"

echo "== aapt2 compile =="
"$BT/aapt2" compile --dir "$SRC/res" -o "$OUT/res.zip"

echo "== aapt2 link =="
"$BT/aapt2" link -o "$OUT/base.apk" \
  -I "$PLAT" \
  --manifest "$SRC/AndroidManifest.xml" \
  -R "$OUT/res.zip" \
  --auto-add-overlay \
  --java "$OUT/gen"

echo "== javac =="
"$JDK/bin/javac" -J-Xmx1g -source 8 -target 8 -nowarn \
  -classpath "$PLAT:$HEV_CLS" \
  -d "$OUT/classes" \
  $(find "$SRC/java" -name "*.java") \
  "$OUT/gen/ir/manjar/vpn/R.java" 2>&1 | grep -vE "^(warning|Note):" | grep -v "bootstrap class path" || true
[ -f "$OUT/classes/ir/manjar/vpn/MainActivity.class" ] || { echo "JAVAC FAILED"; exit 1; }

echo "== d8 =="
( cd "$OUT/classes" && "$JDK/bin/jar" cf "$OUT/myclasses.jar" . )
"$BT/d8" --release --lib "$PLAT" --classpath "$HEV_CLS" \
  --output "$OUT/dex" \
  "$OUT/myclasses.jar" "$HEV_CLS"

echo "== package =="
( cd "$OUT/dex" && zip -q "$OUT/base.apk" classes.dex )
( rm -rf "$OUT/pkg" && mkdir -p "$OUT/pkg/lib/arm64-v8a" && cp "$SRC"/jniLibs/arm64-v8a/*.so "$OUT/pkg/lib/arm64-v8a/" && cd "$OUT/pkg" && zip -q "$OUT/base.apk" lib/arm64-v8a/libxray.so lib/arm64-v8a/libhev-socks5-tunnel.so )
# FIX v1.8.1: assets MUST go under assets/ inside the APK — flat paths caused
# net::ERR_FILE_NOT_FOUND for file:///android_asset/index.html
( cd "$SRC" && zip -q "$OUT/base.apk" \
    assets/index.html assets/logo.png \
    assets/fonts/vazir.woff2 assets/fonts/vazirm.woff2 assets/fonts/vazirb.woff2 )

echo "== zipalign =="
"$BT/zipalign" -f 4 "$OUT/base.apk" "$OUT/aligned.apk"

echo "== sign =="
KS="$ROOT/manjar.keystore"
KS_PASS="${KS_PASS:-manjar172026}"
"$JDK/bin/keytool" -genkeypair -v -keystore "$KS" -alias manjar -keyalg RSA -keysize 2048 \
  -validity 10950 -storepass "$KS_PASS" -keypass "$KS_PASS" \
  -dname "CN=ManjarVPN, OU=Manjar, O=Manjar, L=Tehran, C=IR" 2>/dev/null || true
"$BT/apksigner" sign --ks "$KS" --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
  --out "$OUT/ManjarVPN-1.8.2-android.apk" "$OUT/aligned.apk"
"$BT/apksigner" verify "$OUT/ManjarVPN-1.8.2-android.apk"

echo "== done =="
ls -la "$OUT/ManjarVPN-1.8.2-android.apk"
