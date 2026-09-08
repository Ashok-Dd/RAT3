# RAT3 — Pre-Installation APK Security Scanner

RAT3 is an **Android-only** application that statically analyses an `.apk` file **before you install
it** and produces a risk verdict (`SAFE` / `SUSPICIOUS` / `MALICIOUS`). It is aimed at spotting
remote-access-trojan (RAT) and spyware behaviour in side-loaded apps.

All analysis runs **locally and offline**. RAT3 never installs anything silently — the system
installer dialog is always shown and the user always confirms.

> **Important honesty note**
> Layer 4 is a **rule-weighted heuristic model**, *not* a trained machine-learning classifier.
> There is no bundled `.pkl` / `.tflite` model and no training dataset in this repo. The heuristic
> is transparent and tunable (see `android/app/src/main/kotlin/com/example/rat3/scanner/ScannerConfig.kt`
> and `ml/feature_schema.md`). Training a real classifier is listed under *Future work* below.

---

## How it works

The user opens an APK (via the in-app file picker, or **"Open with RAT3"** from a file manager).
The Kotlin native layer builds a single shared `ApkContext` (parsed once) and runs four analysis
layers, then fuses them into one verdict.

| Layer | Name | What it checks |
|------:|------|----------------|
| 1 | **App Safety Analysis** | Declared permissions (dangerous / suspicious), exported components, target/min SDK, accessibility-service abuse, DeviceAdmin receiver |
| 2 | **Permission–Function Mismatch** | Declared permissions with no matching API in the DEX (over-privilege / obfuscation), plus a small set of always-dangerous APIs (`Runtime.exec`, `DexClassLoader`, `ProcessBuilder`, `ServerSocket`) |
| 3 | **Malware Signature Check** | Substring / regex signatures (`assets/signatures.json`), SHA-256 file blocklist (`assets/blocklist.json`), signing-certificate / repackaging check (`assets/trusted_certs.json`), obfuscation & network (C2) indicators |
| 4 | **Heuristic Risk Model** | A 17-feature vector (see `ml/feature_schema.md`) scored by a transparent weighted rule set |

**Decision engine** (`DecisionEngine.kt`): `weighted = L1·0.20 + L2·0.20 + L3·0.35 + L4·0.25`,
with escalation when a real signature/blocklist hit occurs. Thresholds: `<30` SAFE,
`30–59` SUSPICIOUS, `≥60` MALICIOUS. If a layer fails to analyse, that is stated in the summary and
its error score cannot by itself force a MALICIOUS verdict.

### Architecture

```
Flutter UI (lib/)                       Android native (android/.../kotlin/)
  screens/  splash → home → scanning      MainActivity.kt   ── platform channels
            → result                        scanner/
  services/apk_scanner_service.dart           ApkContext.kt        (parse once)
  services/channels.dart  ─────────────►      Layer1SafetyAnalyzer.kt
  models/scan_result.dart                     Layer2PermissionMismatch.kt
  theme/  widgets/                             Layer3SignatureScanner.kt
                                               Layer4HeuristicModel.kt
                                               DecisionEngine.kt
```

Channels (names shared in `lib/services/channels.dart` and `MainActivity.kt`):
`…/scanner` (scanApk), `…/file` (pickApkFile, getInitialApkPath, onIncomingApk),
`…/install` (installApk), `…/progress` (EventChannel, per-layer progress).

---

## Build & run

Requirements: Flutter 3.38+ / Dart 3.10+, JDK 17, Android SDK, an Android device or emulator
(minSdk 24).

```bash
flutter pub get
flutter analyze          # expect: no issues
flutter test             # Dart unit + smoke tests
(cd android && ./gradlew testDebugUnitTest)   # Kotlin unit tests
flutter build apk --debug
```

### Run on a physical phone

1. On the phone: **Settings → About phone →** tap *Build number* 7× to unlock **Developer options**,
   then enable **USB debugging**.
2. Connect by USB and accept the "Allow USB debugging" prompt.
3. `flutter devices` — the phone should be listed.
4. `flutter run` (hot-reload dev session) **or** `flutter install` (install the debug APK and launch
   manually).
5. First time you install a scanned APK, Android asks you to allow "install unknown apps" for RAT3 —
   grant it and retry.

---

## Repository layout

```
lib/                 Flutter app (see Architecture)
android/             Android host + Kotlin scanner + unit tests
assets/              signatures.json, blocklist.json, trusted_certs.json
ml/                  feature schema + (non-production) training scaffold
test/                Dart tests
```

---

## Future work (out of scope for this build)

- Replace the Layer 4 heuristic with a **trained** classifier (dataset e.g. CICMalDroid-2020 /
  Drebin / MalRadar; on-device inference via TensorFlow Lite).
- Live feeds for the SHA-256 blocklist and certificate reputation.
- Production release signing (keystore + `key.properties`) and R8/shrinking.
- Dynamic / behavioural analysis (this build is purely static).
