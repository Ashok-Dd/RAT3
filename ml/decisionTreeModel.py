"""
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier, export_text, plot_tree
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, matthews_corrcoef,
    confusion_matrix, classification_report
)
from imblearn.over_sampling import SMOTE
import joblib
import warnings
warnings.filterwarnings("ignore")

DATA_PATH  = "./Data/TUANDROMD.csv"
OUTPUT_DIR = "outputs/decision_tree"
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

vt = VarianceThreshold(threshold=0.0)
X_filt = vt.fit_transform(X)
print(f"      Features after variance filter: {X_filt.shape[1]} / {X.shape[1]}")

X_train, X_test, y_train, y_test = train_test_split(
    X_filt, y_enc, test_size=0.20, random_state=42, stratify=y_enc
)

sm = SMOTE(random_state=42)
X_train_res, y_train_res = sm.fit_resample(X_train, y_train)
print(f"      After SMOTE – train size: {X_train_res.shape[0]}  "
      f"(balanced {np.bincount(y_train_res)})\n")

print("[3/6] Hyperparameter search (GridSearchCV, 5-fold) …")

param_grid = {
    "criterion":         ["gini", "entropy"],
    "max_depth":         [5, 10, 15, 20, None],
    "min_samples_split": [2, 5, 10, 20],
    "min_samples_leaf":  [1, 2, 5],
    "class_weight":      ["balanced", None],
    "ccp_alpha":         [0.0, 0.001, 0.005, 0.01],   
}

dt_base = DecisionTreeClassifier(random_state=42)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

search = GridSearchCV(
    dt_base, param_grid,
    scoring="f1_macro", cv=cv,
    n_jobs=-1, verbose=1
)
search.fit(X_train_res, y_train_res)
print(f"      Best params : {search.best_params_}")
print(f"      Best CV F1  : {search.best_score_:.4f}\n")

best_dt = search.best_estimator_

print("[4/6] Evaluating on held-out test set …")
y_pred  = best_dt.predict(X_test)
y_proba = best_dt.predict_proba(X_test)[:, 1]

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

print("[6/6] Saving model …")
joblib.dump({"model": best_dt, "label_encoder": le,
             "variance_filter": vt}, f"{OUTPUT_DIR}/dt_model.pkl")
print(f"      Model saved → {OUTPUT_DIR}/dt_model.pkl")
print("\n✅  Decision Tree training complete.")