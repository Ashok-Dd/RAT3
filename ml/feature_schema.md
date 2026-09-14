# Layer 4 — ML Malware Classifier

Layer 4 of the **pre-installation APK scan** runs a real machine-learning ensemble
**on the device** (Kotlin, offline — no server). It replaces the earlier hand-weighted
heuristic.

## Pipeline

```
APK ──▶ TuandromdFeatures.kt ──▶ 241-bit vector ──▶ VarianceThreshold (241→199)
                                                        │
        ┌───────────────────────────────────────────────┤
        ▼            ▼             ▼            ▼
  RandomForest   DecisionTree   AdaBoost     XGBoost      (assets/ml/*.json)
        └────────────── majority vote + mean P(malware) ──────────────┘
                                   │
                          MlEnsemble → MlResult
                     (verdict, score %, risk level, per-model votes)
```

- **Feature extraction** (`android/.../scanner/ml/TuandromdFeatures.kt`) mirrors
  `ml/apk_extractor.py`: permission-name presence in the manifest, an
  `activityCalled` flag, and ~26 dangerous-API string signatures in the DEX.
- **Models** are exported from the trained scikit-learn / XGBoost bundles by
  `ml/export_models_for_android.py` into `android/app/src/main/assets/ml/`
  (~700 KB total) as compact node arrays. `MlModels.kt` evaluates them.
- **Ensemble** reproduces the Flask app's `ensemble_verdict`: label majority vote,
  risk score = mean malware probability, bands Safe/Low/Medium/High/Critical at
  20/40/60/80.
- The decision engine escalates the overall verdict to MALICIOUS when ≥ 4 of the
  models agree on "malware".

## 241-feature vector (TUANDROMD schema)

Canonical order is `assets/ml/feature_list.json` (identical to the training CSV
columns). Two kinds:

| Prefix | Meaning | Source |
|--------|---------|--------|
| plain name (e.g. `SEND_SMS`, `INTERNET`) | Android permission requested | `AndroidManifest.xml` |
| `activityCalled` | any `<activity>` declared | manifest |
| `L…;->…` (e.g. `Ljava/lang/Runtime;->exec`) | dangerous API referenced | `classes*.dex` strings |

`VarianceThreshold` drops the 42 features that were constant in training, leaving
199 that every model actually uses (`assets/ml/variance_mask.json`).

## Models

Dataset: `Data/TUANDROMD.csv` (4465 samples, 241 binary features, label
malware / goodware). Trained by the `*Model.py` scripts (RandomizedSearchCV,
SMOTE, 5-fold CV). Diagnostics (ROC, confusion matrix, learning curves) are the
PNGs under `models/<name>/`.

| Model | On-device? | Notes |
|-------|:----------:|-------|
| Random Forest | ✅ | avg of per-tree leaf probabilities |
| Decision Tree | ✅ | single tree |
| AdaBoost (SAMME) | ✅ | weighted stump vote → `sigmoid(2·Σ s·w / Σ w)` |
| XGBoost (binary:logistic) | ✅ | `sigmoid(Σ leaf margins)` |
| **Stacking** | ❌ server-only | its KNN base learner is fitted on a 5704-row **SMOTE-resampled** set with interpolated (non-binary) features — impractical to bundle. Still available in `ml/app.py`. |

Kotlin parity with the Python models is enforced by
`android/app/src/test/kotlin/.../MlEnsembleParityTest.kt` against
`ml/parity_samples.json` (±2.5 %).

## Regenerating the assets

```bash
pip install scikit-learn==1.6.1 xgboost joblib numpy pandas
cd ml && python export_models_for_android.py
```

## Future work

- Port the Stacking ensemble (quantised KNN matrix) or retrain a single strong
  model to replace the ensemble.
- Retrain on a fresher corpus (AndroZoo + VirusTotal labels); the TUANDROMD
  schema is dated.
- On-device feature extraction currently uses a string-scan of the DEX; a proper
  DEX parser would reduce false negatives from obfuscation.
