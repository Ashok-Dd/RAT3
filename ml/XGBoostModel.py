"""
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV
from sklearn.preprocessing import LabelEncoder
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, matthews_corrcoef,
    confusion_matrix, classification_report
)
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier, plot_importance
import joblib
import warnings
warnings.filterwarnings("ignore")

DATA_PATH  = "./Data/TUANDROMD.csv"
OUTPUT_DIR = "outputs/xgboost"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("[1/6] Loading dataset …")
df = pd.read_csv(DATA_PATH)
print(f"      Shape: {df.shape}")
print(f"      Class distribution:\n{df['Label'].value_counts()}\n")

X = df.drop(columns=["Label"])
y = df["Label"]

print("[2/6] Preprocessing …")

mask  = y.notna()
X     = X[mask].reset_index(drop=True)
y     = y[mask].reset_index(drop=True)
print(f"      Dropped {(~mask).sum()} NaN-label rows. Remaining: {len(y)}")

le = LabelEncoder()
y_enc = le.fit_transform(y)
print(f"      Classes: {le.classes_}  →  {list(range(len(le.classes_)))}")

X = X.fillna(0).astype(np.float32)
X.columns = [c.replace("[", "_").replace("]", "_").replace("<", "_").replace(">", "_")
               .replace(";", "_").replace("/", "_").replace("->", "_").replace(",", "_")
             for c in X.columns]

vt = VarianceThreshold(threshold=0.0)
X_filt = vt.fit_transform(X)
feature_names = list(X.columns[vt.get_support()])
print(f"      Features after variance filter: {X_filt.shape[1]} / {X.shape[1]}")

X_train, X_test, y_train, y_test = train_test_split(
    X_filt, y_enc, test_size=0.20, random_state=42, stratify=y_enc
)

neg, pos = np.bincount(y_train)
scale_pos_weight = neg / pos
print(f"      scale_pos_weight = {scale_pos_weight:.3f}  (neg={neg}, pos={pos})\n")

print("[3/6] Hyperparameter search (RandomizedSearchCV, 3-fold) …")

param_dist = {
    "n_estimators":      [100, 200, 300, 500],
    "max_depth":         [3, 5, 7, 9],
    "learning_rate":     [0.01, 0.05, 0.1, 0.2],
    "subsample":         [0.6, 0.8, 1.0],
    "colsample_bytree":  [0.6, 0.8, 1.0],
    "min_child_weight":  [1, 3, 5],
    "gamma":             [0, 0.1, 0.3, 0.5],
    "reg_alpha":         [0, 0.1, 1.0],
    "reg_lambda":        [1.0, 2.0, 5.0],
}

xgb_base = XGBClassifier(
    scale_pos_weight=scale_pos_weight,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1,
    tree_method="hist",          
)

cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
search = RandomizedSearchCV(
    xgb_base, param_dist,
    n_iter=30, scoring="f1_macro",
    cv=cv, n_jobs=-1, random_state=42, verbose=1
)
search.fit(X_train, y_train)
print(f"      Best params : {search.best_params_}")
print(f"      Best CV F1  : {search.best_score_:.4f}\n")

best_xgb = search.best_estimator_

print("[3b] Final refit with early stopping …")
X_tr, X_val, y_tr, y_val = train_test_split(
    X_train, y_train, test_size=0.15, random_state=42, stratify=y_train
)

best_params = search.best_params_.copy()
final_xgb = XGBClassifier(
    **best_params,
    scale_pos_weight=scale_pos_weight,
    use_label_encoder=False,
    eval_metric="logloss",
    early_stopping_rounds=30,
    random_state=42,
    n_jobs=-1,
    tree_method="hist",
)
final_xgb.fit(
    X_tr, y_tr,
    eval_set=[(X_val, y_val)],
    verbose=50,
)
print(f"      Best iteration: {final_xgb.best_iteration}\n")

print("[4/6] Evaluating on held-out test set …")
y_pred  = final_xgb.predict(X_test)
y_proba = final_xgb.predict_proba(X_test)[:, 1]

acc   = accuracy_score(y_test, y_pred)
prec  = precision_score(y_test, y_pred, average="macro")
rec   = recall_score(y_test, y_pred, average="macro")
f1    = f1_score(y_test, y_pred, average="macro")
auc   = roc_auc_score(y_test, y_proba)
mcc   = matthews_corrcoef(y_test, y_pred)

print(f"\n{'='*45}")
print(f"  Accuracy          : {acc:.4f}")
print(f"  Precision (macro) : {prec:.4f}")
print(f"  Recall    (macro) : {rec:.4f}")
print(f"  F1        (macro) : {f1:.4f}")
print(f"  ROC-AUC           : {auc:.4f}")
print(f"  MCC               : {mcc:.4f}")
print(f"{'='*45}\n")
print(classification_report(y_test, y_pred, target_names=le.classes_))

print("[5/6] Saving plots …")

cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Oranges",
            xticklabels=le.classes_, yticklabels=le.classes_, ax=ax)
ax.set_title("XGBoost – Confusion Matrix")
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/confusion_matrix.png", dpi=150)
plt.close()

importances = final_xgb.feature_importances_
top20_idx   = np.argsort(importances)[-20:][::-1]
top20_names = [feature_names[i] for i in top20_idx[::-1]]
top20_vals  = importances[top20_idx[::-1]]
fig, ax = plt.subplots(figsize=(10, 6))
ax.barh(top20_names, top20_vals, color="darkorange")
ax.set_title("XGBoost – Top 20 Feature Importances (gain)")
ax.set_xlabel("F-score")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/feature_importance.png", dpi=150)
plt.close()

results = final_xgb.evals_result()
train_loss = results["validation_0"]["logloss"]
fig, ax = plt.subplots(figsize=(8, 4))
ax.plot(train_loss, label="Validation Log-loss")
ax.axvline(final_xgb.best_iteration, color="red",
           linestyle="--", label=f"Best iter={final_xgb.best_iteration}")
ax.set_xlabel("Boosting Rounds"); ax.set_ylabel("Log-loss")
ax.set_title("XGBoost – Validation Loss Curve")
ax.legend()
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/loss_curve.png", dpi=150)
plt.close()

print("[6/6] Saving model …")
joblib.dump({"model": final_xgb, "label_encoder": le,
             "variance_filter": vt}, f"{OUTPUT_DIR}/xgb_model.pkl")
print(f"      Model saved → {OUTPUT_DIR}/xgb_model.pkl")
print("\n✅  XGBoost training complete.")