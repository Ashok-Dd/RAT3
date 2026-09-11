# RAT3 — Android RAT / Spyware Defence

RAT3 is an **Android-only** security app with two halves:

1. **Pre-installation scanner** — analyse an `.apk` *before* you install it and get a
   `SAFE` / `SUSPICIOUS` / `MALICIOUS` verdict, ending with a real on-device ML classifier.
2. **Post-installation monitor** — a persistent background service that watches the live device
   for remote-access-trojan / spyware behaviour (sensor abuse, data exfiltration, rogue
   accessibility services, root, sideloaded risky apps) and raises notifications.

Everything runs **locally and offline**. Installing an APK always goes through the system
installer dialog — RAT3 never installs anything silently.

> **Honesty notes**
> - The pre-install ML layer is a real 4-model ensemble (Random Forest, Decision Tree, AdaBoost,
>   XGBoost) exported from the trained scikit-learn / XGBoost models and evaluated in Kotlin.
>   The 5th model (Stacking) stays server-only — its KNN base learner needs a SMOTE-resampled
>   training set that can't be bundled compactly. See `ml/feature_schema.md`.
> - The monitor needs `QUERY_ALL_PACKAGES` and `PACKAGE_USAGE_STATS` to see other apps. This is a
>   **sideload / enterprise** posture, not a Play-Store-friendly one.
> - The release build is minified (R8) and signed with a real upload keystore
>   (`android/key.properties`, gitignored — not committed). Without that file present, a fresh
>   checkout's release build automatically falls back to the debug key so `assembleRelease` still
>   works locally.

---

## The app

Five bottom-nav tabs (post-install monitor), with the pre-install scanner folded into the
**Scanner** tab behind a *Device Monitor / Scan an APK* toggle.

| Tab | What it shows |
|-----|---------------|
| **Dashboard** | Live risk ball, active/critical alert counts, connection count, risk breakdown |
| **Network** | Per-app upload/download bytes, flagged high-upload apps |
| **Alerts** | Every finding from all layers, filterable by severity, with notifications |
| **Scanner** | *Device Monitor*: manual scan, auto-scan interval, layer status, Sensor Scan, Scan All Apps. *Scan an APK*: pick an APK → 4-layer pre-install analysis |
| **Settings** | Monitoring / notification toggles, **Fix permissions** (re-run onboarding), reset risk score |

A first-run **onboarding** screen requests: notifications, usage access, battery-optimisation
exemption, and camera/mic/location. Monitoring (and the foreground service) start once onboarding
finishes; you can skip and grant later.

### Pre-installation scan — 4 layers

| Layer | Checks |
|------:|--------|
| 1 App Safety | dangerous / suspicious permissions, exported components, target SDK, **accessibility-service abuse**, DeviceAdmin |
| 2 Permission↔Function | permissions declared with no matching API in the DEX; `Runtime.exec` / `DexClassLoader` / `ProcessBuilder` / `ServerSocket` |
| 3 Signatures & Reputation | substring/regex signatures, **SHA-256 file blocklist**, **signing-cert / repackaging check**, obfuscation & C2 network indicators |
| 4 ML Malware Classifier | 241-feature TUANDROMD vector → 4-model ensemble → majority vote + mean malware probability |

`DecisionEngine`: `weighted = L1·0.20 + L2·0.20 + L3·0.35 + L4·0.25`; escalate to MALICIOUS on a
Layer-3 hard hit or a ≥ 4/4 ML "malware" vote. Thresholds: `<30` SAFE, `30–59` SUSPICIOUS, `≥60`
MALICIOUS.

### Post-installation monitor — 5 layers

Runtime Monitor (CPU / memory / processes / root, 15 s) · Network Monitor (per-app TX deltas,
C2 indicators, 20 s) · Permission Tracker (sensitive-permission background abuse) · Alert Engine
(dedup, persistence, notifications) · Risk Engine (60 s — a 65-signal `DeviceFeatures` snapshot
scored by a weighted rule engine). A native **foreground service** re-runs a self-contained Kotlin
scan every 5–180 min (default 10), survives app-kill (`START_STICKY`) and reboot (`BootReceiver`).

---

## Architecture

```
lib/
  main.dart / _RootGate         onboarding gate → AppShell
  core/{constants,theme,utils}   one AppTheme (neon-cyber), one risk-colour helper
  data/
    models/app_models.dart
    services/  app_controller (orchestrator) · platform_channel_service ·
               notification_service · storage_service · app_scanner_service
  layers/  runtime_monitor · network_monitor · permission_tracker ·
           alert_engine · risk_engine · feature_engine
  presentation/  app_shell · onboarding · dashboard · network · alerts ·
                 scanner (segmented) · sensors · app_scan · settings
  features/apk_scan/  apk_scan_landing · scanning_screen · result_screen ·
                      services/{apk_scanner_service,channels} · models/scan_result
  widgets/  common_widgets (CyberCard, SectionHeader, badges, ScanPulse) · risk_ball

android/app/src/main/kotlin/com/example/rat3/
  MainActivity.kt          five channels: /security (monitor) + /scanner /file /install /progress
  ScanForegroundService.kt · ScanAlarmReceiver.kt · BootReceiver.kt
  scanner/  ApkContext (parse once) · Layer1-3 · Layer4MlClassifier · DecisionEngine ·
            Signatures · Reputation · ScannerConfig · ScannerUtils · ml/{MlModels,TuandromdFeatures}
android/app/src/main/assets/
  signatures.json · blocklist.json · trusted_certs.json · ml/*.json (exported models)

ml/   Flask app (app.py) + training scripts (*Model.py) + trained .pkl + TUANDROMD.csv
      export_models_for_android.py  →  assets/ml/*.json  +  parity_samples.json
```

Platform channels (names shared in `lib/features/apk_scan/services/channels.dart` &
`lib/data/services/platform_channel_service.dart` ↔ `MainActivity.kt`).

---

## Build & run

Requirements: Flutter 3.38+ / Dart 3.10+, JDK 17, Android SDK (compileSdk 36), an Android device
or emulator (minSdk 24).

```bash
flutter pub get
flutter analyze                       # 0 issues
flutter test                          # Dart tests
(cd android && ./gradlew :app:testDebugUnitTest)   # Kotlin tests (incl. ML parity)
flutter build apk --debug
flutter build apk --release           # minified, real-signed if android/key.properties exists
flutter build appbundle --release     # for Play Store upload
```

Bump the version before a release build: `version:` in `pubspec.yaml` is `<versionName>+<versionCode>`
(e.g. `1.1.0+2`) — Android reads both straight from it, so there's nothing to change in Gradle.
Always increment `versionCode` (the number after `+`); Play Store rejects a re-upload that doesn't.

### On a physical phone

1. Phone: **Settings → About phone →** tap *Build number* 7×, then enable **USB debugging**.
2. Plug in, accept the prompt. `flutter devices` should list it.
3. `flutter run` (or `flutter install`).
4. Complete onboarding — grant notifications, **usage access** (opens a settings page),
   battery exemption, camera/mic.
5. The foreground-service notification appears and monitoring begins.

### Regenerating the ML assets

```bash
pip install scikit-learn==1.6.1 xgboost joblib numpy pandas
cd ml && python export_models_for_android.py
```

### The Flask research tool (optional, not part of the app)

```bash
cd ml && pip install -r requirements.txt && python app.py    # http://localhost:5000
```
Upload an APK to run all **five** models (Stacking included) server-side.

---

## Tests

- `test/scan_result_parsing_test.dart` — channel JSON parsing
- `test/widget_test.dart` — shared-widget + theme smoke test
- `test/alert_engine_test.dart` — 3-tier alert dedup + notification suppression
- `test/rule_based_scorer_test.dart` — the real Dashboard risk-scoring engine
- `android/.../DecisionEngineTest.kt`, `ScannerUtilsTest.kt` — verdict math, JSON schema
- `android/.../Layer1SafetyAnalyzerTest.kt`, `Layer2PermissionMismatchTest.kt`,
  `Layer3SignatureScannerTest.kt` — per-layer scoring rules (Layer3 via Robolectric, to read the
  real bundled `assets/*.json`)
- `android/.../ml/MlEnsembleParityTest.kt` — Kotlin ML evaluators vs the Python models (±2.5 %)

---

## Future work

- Port Stacking on-device (quantised KNN matrix) or retrain a single strong model.
- Retrain on a fresher corpus (AndroZoo + VirusTotal); TUANDROMD is dated.
- Real DEX parser for feature extraction (currently a string scan).
- Live blocklist / cert-reputation feeds (`assets/blocklist.json` and `trusted_certs.json` ship
  with placeholder hashes only — see each file's `_comment`).
- Play Store publish-readiness (deliberately not started): Play-compliant package-visibility
  instead of `QUERY_ALL_PACKAGES`, Data Safety form, hosted privacy policy, real app icon,
  Crashlytics, Play App Signing enrollment.
