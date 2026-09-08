# Layer 4 — Feature Schema

Layer 4 (`Layer4HeuristicModel.kt`) extracts a fixed **17-feature vector** from the APK and the
Layer 1–3 results, then scores it with the transparent weighted rules in `HeuristicRiskModel`.

> This is **not** a trained machine-learning model. There is no `.pkl` / `.tflite` file and no
> training dataset in this repository. The weights live in `ScannerConfig.Layer4` and are hand-set.
> See *Future work* at the bottom for what a real classifier would need.

## Vector layout

| # | Name | Type | Source | Meaning |
|--:|------|------|--------|---------|
| 0 | `numPermissions` | int | `ApkContext.permissions` | Total declared permissions |
| 1 | `numDangerousPermissions` | int | `KnownPermissions.DANGEROUS` ∩ declared | Runtime-dangerous permissions |
| 2 | `numSuspiciousPermissions` | int | `KnownPermissions.SUSPICIOUS` ∩ declared | Rarely-legitimate permissions |
| 3 | `numExportedComponents` | int | `ApkContext.exportedComponentCount` | Components exported to other apps |
| 4 | `targetSdk` | int | `ApkContext.targetSdk` | `android:targetSdkVersion` (0 = unknown) |
| 5 | `hasSmsPermission` | 0/1 | declared permissions | Any `*_SMS` permission present |
| 6 | `hasCameraPermission` | 0/1 | declared permissions | `CAMERA` present |
| 7 | `hasLocationPermission` | 0/1 | declared permissions | Any `*_LOCATION` permission present |
| 8 | `hasAudioPermission` | 0/1 | declared permissions | `RECORD_AUDIO` present |
| 9 | `numNativeLibs` | int | `ApkContext.nativeLibs` | `.so` entries in the APK |
| 10 | `hasObfuscation` | 0/1 | Layer 3 findings (`category=obfuscation`) | Large Base64 blobs in resources |
| 11 | `dexSizeKB` | int | `ApkContext.dexText.length / 1024` | Size of scanned DEX text (capped at 16 MB) |
| 12 | `numBase64Blobs` | int | resource text scan | Count of ≥400-char Base64 blobs |
| 13 | `hasRawIpAddresses` | 0/1 | Layer 3 findings (`category=network`) | Hardcoded `IP:port` present |
| 14 | `layer1RiskScore` | int 0–100 | Layer 1 result | App-safety score |
| 15 | `layer2RiskScore` | int 0–100 | Layer 2 result | Permission-mismatch score |
| 16 | `layer3RiskScore` | int 0–100 | Layer 3 result | Signature/reputation score |

## Heuristic rules (`HeuristicRiskModel.score`)

Starting score = `mean(feat 14,15,16) × 0.30`, then additive:

| Condition | Points | Rationale |
|-----------|-------:|-----------|
| `hasSms & hasAudio & hasLocation & numDangerous ≥ 6` | +25 | Spyware capability triad |
| `hasRawIps & hasObfuscation` | +20 | Obfuscated hardcoded C2 |
| `dexSizeKB > 8000 & numBase64 ≥ 8 & numNativeLibs > 0` | +15 | Heavy hidden payload |
| `hasSms & numSuspicious ≥ 2` | +15 | SMS abuse + privileged perms |

Final score is clamped to 0–100. Labels: `≥60` ELEVATED, `≥30` MODERATE, else LOW.

## Future work — training a real classifier

1. **Dataset.** Labelled APKs, e.g. CICMalDroid-2020, Drebin, MalRadar, or AndroZoo (+ VirusTotal
   labels). Keep a benign set from a recent Play-store crawl.
2. **Feature extraction.** Run the same 17 features over every sample (extend `ApkContext` to emit
   the vector as JSON for offline collection).
3. **Train / evaluate.** `ml/train_model_scaffold.py` is a starting point (currently synthetic
   data — replace `generate_dummy_data`). Report precision / recall / ROC-AUC and a confusion
   matrix; watch the benign false-positive rate.
4. **On-device inference.** Export to TensorFlow Lite, bundle under
   `android/app/src/main/assets/`, add the `org.tensorflow:tensorflow-lite` dependency, and
   replace the `HeuristicRiskModel.score` call in `Layer4HeuristicModel`.
5. **Persist scaling.** If the model needs standardised inputs, store the scaler parameters and
   apply them identically in Kotlin.
