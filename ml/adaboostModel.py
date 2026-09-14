"""
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

from sklearn.model_selection   import (train_test_split, StratifiedKFold,
                                        RandomizedSearchCV, learning_curve,
                                        cross_validate)
from sklearn.preprocessing     import LabelEncoder
from sklearn.ensemble          import AdaBoostClassifier
from sklearn.tree              import DecisionTreeClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics           import (accuracy_score, precision_score,
                                        recall_score, f1_score, roc_auc_score,
                                        matthews_corrcoef, confusion_matrix,
                                        classification_report, roc_curve)
from imblearn.over_sampling    import SMOTE
import joblib
import warnings
warnings.filterwarnings("ignore")

DATA_PATH  = "./Data/TUANDROMD.csv"
OUTPUT_DIR = "outputs/adaboost"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 60)
print("  ADABOOST – Android Malware Detection")
print("=" * 60)
print("\n[1/7] Loading dataset …")
df = pd.read_csv(DATA_PATH)
print(f"      Shape              : {df.shape}")
print(f"      Class distribution :\n{df['Label'].value_counts()}\n")

X_raw = df.drop(columns=["Label"])
y_raw = df["Label"]

print("[2/7] Preprocessing …")

mask  = y_raw.notna()
X_raw = X_raw[mask].reset_index(drop=True)
y_raw = y_raw[mask].reset_index(drop=True)
print(f"      Dropped {(~mask).sum()} NaN-label rows  →  {len(y_raw)} samples remain")

le    = LabelEncoder()
y_enc = le.fit_transform(y_raw)           
print(f"      Classes : {le.classes_}  →  {list(range(len(le.classes_)))}")

X_raw = X_raw.fillna(0).astype(np.float32)

vt     = VarianceThreshold(threshold=0.0)
X_filt = vt.fit_transform(X_raw)
feat_names = np.array(X_raw.columns[vt.get_support()])
print(f"      Features after VarianceThreshold : {X_filt.shape[1]} / {X_raw.shape[1]}")

X_train, X_test, y_train, y_test = train_test_split(
    X_filt, y_enc, test_size=0.20, random_state=42, stratify=y_enc
)

sm = SMOTE(random_state=42)
X_train_res, y_train_res = sm.fit_resample(X_train, y_train)
print(f"      After SMOTE – train : {X_train_res.shape[0]}  "
      f"{dict(zip(le.classes_, np.bincount(y_train_res)))}\n")

print("[3/7] Hyperparameter search (RandomizedSearchCV, 5-fold, 25 iter) …")

param_dist = {
    "n_estimators":              [50, 100, 200, 300, 500],
    "learning_rate":             [0.01, 0.05, 0.1, 0.5, 1.0],
    "estimator__max_depth":      [1, 2, 3, 4],
    "estimator__class_weight":   ["balanced", None],
    "estimator__min_samples_leaf": [1, 2, 5],
}

base = DecisionTreeClassifier(random_state=42)
ada_base = AdaBoostClassifier(estimator=base, algorithm="SAMME", random_state=42)

cv5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
search = RandomizedSearchCV(
    ada_base, param_dist,
    n_iter=25, scoring="f1_macro",
    cv=cv5, n_jobs=-1, random_state=42, verbose=1,
    return_train_score=True,
)
search.fit(X_train_res, y_train_res)

print(f"\n      Best params : {search.best_params_}")
print(f"      Best CV F1  : {search.best_score_:.4f}\n")

best_params = search.best_params_

print("[4/7] Training final AdaBoost model …")

best_base = DecisionTreeClassifier(
    max_depth          = best_params["estimator__max_depth"],
    class_weight       = best_params["estimator__class_weight"],
    min_samples_leaf   = best_params["estimator__min_samples_leaf"],
    random_state       = 42,
)
best_ada = AdaBoostClassifier(
    estimator     = best_base,
    n_estimators  = best_params["n_estimators"],
    learning_rate = best_params["learning_rate"],
    algorithm     = "SAMME",
    random_state  = 42,
)
best_ada.fit(X_train_res, y_train_res)
print(f"      n_estimators used : {best_ada.n_estimators}")

print("\n[5/7] Computing staged error curve (generalisation during boosting) …")

train_staged, test_staged = [], []
for train_pred, test_pred in zip(
    best_ada.staged_predict(X_train_res),
    best_ada.staged_predict(X_test)
):
    train_staged.append(1.0 - accuracy_score(y_train_res, train_pred))
    test_staged.append(1.0 - accuracy_score(y_test,       test_pred))

n_rounds = list(range(1, len(train_staged) + 1))
print(f"      Final train error : {train_staged[-1]:.4f}")
print(f"      Final test  error : {test_staged[-1]:.4f}")
print(f"      Generalisation gap: {test_staged[-1] - train_staged[-1]:.4f}")

print("\n[6/7] 5-fold CV + learning curve …")

cv_results = cross_validate(
    best_ada, X_train_res, y_train_res,
    cv=cv5,
    scoring={"accuracy":"accuracy","f1_macro":"f1_macro",
             "roc_auc":"roc_auc","precision":"precision_macro",
             "recall":"recall_macro"},
    return_train_score=True, n_jobs=-1,
)

print(f"\n  {'Metric':<20} {'Train':>10}  {'CV':>10}  {'Gap':>8}  Status")
print("  " + "-"*60)
for m in ["accuracy","f1_macro","roc_auc","precision","recall"]:
    tr = cv_results[f"train_{m}"].mean()
    cv = cv_results[f"test_{m}"].mean()
    gap = tr - cv
    flag = "⚠ overfit" if gap > 0.05 else "✓ good"
    print(f"  {m:<20} {tr:>10.4f}  {cv:>10.4f}  {gap:>8.4f}  {flag}")

train_sz, lc_tr, lc_val = learning_curve(
    best_ada, X_train_res, y_train_res,
    cv=cv5, scoring="f1_macro",
    train_sizes=np.linspace(0.10, 1.0, 10),
    n_jobs=-1, shuffle=True, random_state=42,
)
lc_tr_mean  = lc_tr.mean(axis=1);  lc_tr_std  = lc_tr.std(axis=1)
lc_val_mean = lc_val.mean(axis=1); lc_val_std = lc_val.std(axis=1)

print("\n[7/7] Final evaluation on held-out test set …")
y_pred  = best_ada.predict(X_test)
y_proba = best_ada.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, average="macro")
rec  = recall_score(y_test, y_pred, average="macro")
f1   = f1_score(y_test, y_pred, average="macro")
auc  = roc_auc_score(y_test, y_proba)
mcc  = matthews_corrcoef(y_test, y_pred)

print(f"\n{'='*50}")
print(f"  Accuracy          : {acc:.4f}")
print(f"  Precision (macro) : {prec:.4f}")
print(f"  Recall    (macro) : {rec:.4f}")
print(f"  F1        (macro) : {f1:.4f}")
print(f"  ROC-AUC           : {auc:.4f}")
print(f"  MCC               : {mcc:.4f}")
print(f"{'='*50}\n")
print(classification_report(y_test, y_pred, target_names=le.classes_))

print("Saving plots …")
plt.rcParams.update({"font.size": 10, "axes.titlesize": 11})
cm = confusion_matrix(y_test, y_pred)
fpr_arr, tpr_arr, _ = roc_curve(y_test, y_proba)

metrics_labels = ["accuracy","f1_macro","roc_auc","precision","recall"]
tr_means = [cv_results[f"train_{m}"].mean() for m in metrics_labels]
cv_means = [cv_results[f"test_{m}"].mean()  for m in metrics_labels]
tr_stds  = [cv_results[f"train_{m}"].std()  for m in metrics_labels]
cv_stds  = [cv_results[f"test_{m}"].std()   for m in metrics_labels]

fig, ax = plt.subplots(figsize=(9, 4))
ax.plot(n_rounds, train_staged, color="steelblue",  lw=2, label="Train error")
ax.plot(n_rounds, test_staged,  color="darkorange", lw=2, label="Test error")
best_n = int(np.argmin(test_staged)) + 1
ax.axvline(best_n, color="green", linestyle="--",
           label=f"Best test @ round {best_n} ({min(test_staged):.4f})")
ax.set_xlabel("Boosting Rounds (n_estimators)")
ax.set_ylabel("Error Rate  (1 – Accuracy)")
ax.set_title("AdaBoost – Staged Error During Boosting\n"
             "(Generalisation curve: watch for test error rising = overfit)")
ax.legend(); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/staged_error_curve.png", dpi=150)
plt.close()
print(f"  ✓  staged_error_curve.png")

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(train_sz, lc_tr_mean,  "o-", color="steelblue",  label="Train F1")
ax.fill_between(train_sz, lc_tr_mean-lc_tr_std,  lc_tr_mean+lc_tr_std,  alpha=0.12, color="steelblue")
ax.plot(train_sz, lc_val_mean, "s-", color="darkorange", label="CV F1")
ax.fill_between(train_sz, lc_val_mean-lc_val_std, lc_val_mean+lc_val_std, alpha=0.12, color="darkorange")
gap = lc_tr_mean[-1] - lc_val_mean[-1]
ax.annotate(f"Gap={gap:.3f}", xy=(train_sz[-1], (lc_tr_mean[-1]+lc_val_mean[-1])/2),
            xytext=(-100, 5), textcoords="offset points",
            arrowprops=dict(arrowstyle="->"), fontsize=9,
            color="red" if gap > 0.05 else "green")
ax.set_xlabel("Training Set Size"); ax.set_ylabel("F1 Macro")
ax.set_title("AdaBoost – Learning Curve (Bias-Variance)")
ax.legend(); ax.set_ylim(0, 1.05); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/learning_curve.png", dpi=150)
plt.close()
print(f"  ✓  learning_curve.png")

fig, ax = plt.subplots(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="YlOrRd",
            xticklabels=le.classes_, yticklabels=le.classes_, ax=ax)
ax.set_title("AdaBoost – Confusion Matrix (Test Set)")
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/confusion_matrix.png", dpi=150)
plt.close()
print(f"  ✓  confusion_matrix.png")

fig, ax = plt.subplots(figsize=(6, 5))
ax.plot(fpr_arr, tpr_arr, color="darkorange", lw=2, label=f"AUC={auc:.4f}")
ax.plot([0,1],[0,1],"k--", lw=1)
ax.set_xlabel("FPR"); ax.set_ylabel("TPR")
ax.set_title("AdaBoost – ROC Curve"); ax.legend(); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/roc_curve.png", dpi=150)
plt.close()
print(f"  ✓  roc_curve.png")

x = np.arange(len(metrics_labels))
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(x-0.2, tr_means, 0.4, yerr=tr_stds, capsize=4,
       label="Train", color="steelblue", alpha=0.85)
ax.bar(x+0.2, cv_means, 0.4, yerr=cv_stds, capsize=4,
       label="CV",    color="darkorange", alpha=0.85)
ax.set_xticks(x)
ax.set_xticklabels(["Accuracy","F1 Macro","ROC-AUC","Precision","Recall"])
ax.set_ylim(0, 1.18); ax.set_ylabel("Score")
ax.set_title("AdaBoost – Train vs CV Generalisation")
ax.legend(); ax.grid(True, axis="y", alpha=0.3)
for i,(tr,cv) in enumerate(zip(tr_means,cv_means)):
    g = tr-cv
    ax.text(i, max(tr,cv)+0.05, f"Δ{g:.3f}", ha="center",
            fontsize=8, color="red" if g>0.05 else "green", fontweight="bold")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/train_vs_cv_metrics.png", dpi=150)
plt.close()
print(f"  ✓  train_vs_cv_metrics.png")

fig = plt.figure(figsize=(18, 10))
gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.42, wspace=0.36)

ax0 = fig.add_subplot(gs[0, 0])
ax0.plot(n_rounds, train_staged, color="steelblue",  lw=1.5, label="Train")
ax0.plot(n_rounds, test_staged,  color="darkorange", lw=1.5, label="Test")
ax0.axvline(best_n, color="green", linestyle="--", lw=1)
ax0.set_xlabel("Rounds"); ax0.set_ylabel("Error")
ax0.set_title("Staged Error (Boosting)"); ax0.legend(fontsize=8); ax0.grid(True, alpha=0.3)

ax1 = fig.add_subplot(gs[0, 1])
ax1.plot(train_sz, lc_tr_mean,  "o-", color="steelblue",  lw=1.5, label="Train")
ax1.fill_between(train_sz, lc_tr_mean-lc_tr_std, lc_tr_mean+lc_tr_std, alpha=0.12, color="steelblue")
ax1.plot(train_sz, lc_val_mean, "s-", color="darkorange", lw=1.5, label="CV")
ax1.fill_between(train_sz, lc_val_mean-lc_val_std, lc_val_mean+lc_val_std, alpha=0.12, color="darkorange")
ax1.set_xlabel("Train size"); ax1.set_ylabel("F1 Macro")
ax1.set_title("Learning Curve"); ax1.legend(fontsize=8); ax1.set_ylim(0,1.05); ax1.grid(True, alpha=0.3)

ax2 = fig.add_subplot(gs[0, 2])
xi = np.arange(5)
ax2.bar(xi-0.2, cv_results["train_f1_macro"], 0.4, label="Train", color="steelblue", alpha=0.85)
ax2.bar(xi+0.2, cv_results["test_f1_macro"],  0.4, label="CV",    color="darkorange", alpha=0.85)
ax2.set_xticks(xi); ax2.set_xticklabels([f"F{i+1}" for i in range(5)], fontsize=8)
ax2.set_ylabel("F1 Macro"); ax2.set_title("5-Fold CV F1"); ax2.set_ylim(0,1.12)
ax2.legend(fontsize=8); ax2.grid(True, axis="y", alpha=0.3)

ax3 = fig.add_subplot(gs[1, 0])
xm = np.arange(len(metrics_labels))
ax3.bar(xm-0.2, tr_means, 0.4, label="Train", color="steelblue", alpha=0.85)
ax3.bar(xm+0.2, cv_means, 0.4, label="CV",    color="darkorange", alpha=0.85)
ax3.set_xticks(xm); ax3.set_xticklabels(["Acc","F1","AUC","Prec","Rec"], fontsize=8)
ax3.set_ylim(0, 1.18); ax3.set_title("All Metrics: Train vs CV")
ax3.legend(fontsize=8); ax3.grid(True, axis="y", alpha=0.3)

ax4 = fig.add_subplot(gs[1, 1])
sns.heatmap(cm, annot=True, fmt="d", cmap="YlOrRd",
            xticklabels=le.classes_, yticklabels=le.classes_,
            ax=ax4, cbar=False, annot_kws={"size":11})
ax4.set_title("Confusion Matrix (Test)"); ax4.set_xlabel("Pred"); ax4.set_ylabel("Actual")

ax5 = fig.add_subplot(gs[1, 2])
ax5.plot(fpr_arr, tpr_arr, color="darkorange", lw=2, label=f"AUC={auc:.4f}")
ax5.plot([0,1],[0,1],"k--",lw=1)
ax5.set_xlabel("FPR"); ax5.set_ylabel("TPR"); ax5.set_title("ROC Curve")
ax5.legend(fontsize=9); ax5.grid(True, alpha=0.3)

fig.suptitle(
    f"AdaBoost – Generalisation Dashboard\n"
    f"CV F1={cv_results['test_f1_macro'].mean():.4f}  |  Test F1={f1:.4f}  |  Test AUC={auc:.4f}",
    fontsize=12, fontweight="bold"
)
plt.savefig(f"{OUTPUT_DIR}/generalisation_dashboard.png", dpi=150, bbox_inches="tight")
plt.close()
print(f"  ✓  generalisation_dashboard.png")

# ─────────────────────────────────────────────────────────
# Save model
# ─────────────────────────────────────────────────────────
joblib.dump(
    {"model": best_ada, "label_encoder": le, "variance_filter": vt},
    f"{OUTPUT_DIR}/adaboost_model.pkl"
)

# ─────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────
cv_f1_mean = cv_results["test_f1_macro"].mean()
cv_f1_std  = cv_results["test_f1_macro"].std()
train_f1   = cv_results["train_f1_macro"].mean()
gap_final  = train_f1 - cv_f1_mean

print(f"\n{'='*60}")
print("  GENERALISATION SUMMARY – ADABOOST")
print(f"{'='*60}")
print(f"  Best boosting round (lowest test error) : {best_n}")
print(f"  CV  F1  mean ± std  (5-fold)            : {cv_f1_mean:.4f} ± {cv_f1_std:.4f}")
print(f"  Test F1  (held-out 20%)                 : {f1:.4f}")
print(f"  Test AUC (held-out 20%)                 : {auc:.4f}")
print(f"  Train–CV F1 gap                         : {gap_final:.4f}  "
      f"{'✓ generalises well' if gap_final < 0.05 else '⚠ possible overfit'}")
print(f"{'='*60}")
print(f"\n✅  AdaBoost training complete.")
print(f"\n  All outputs → {OUTPUT_DIR}/")
for f_name in sorted(os.listdir(OUTPUT_DIR)):
    print(f"    • {f_name}")