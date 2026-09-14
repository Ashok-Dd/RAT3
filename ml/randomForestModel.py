
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from sklearn.model_selection  import (train_test_split, StratifiedKFold,
                                       RandomizedSearchCV, learning_curve,
                                       cross_validate)
from sklearn.preprocessing    import LabelEncoder
from sklearn.ensemble         import RandomForestClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics          import (accuracy_score, precision_score,
                                       recall_score, f1_score, roc_auc_score,
                                       matthews_corrcoef, confusion_matrix,
                                       classification_report, roc_curve)
from imblearn.over_sampling   import SMOTE
import joblib
import warnings
warnings.filterwarnings("ignore")

DATA_PATH  = "./Data/TUANDROMD.csv"
OUTPUT_DIR = "outputs/random_forest"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 60)
print("  RANDOM FOREST – Android Malware Detection")
print("=" * 60)
print("\n[1/8] Loading dataset …")
df = pd.read_csv(DATA_PATH)
print(f"      Shape              : {df.shape}")
print(f"      Class distribution :\n{df['Label'].value_counts()}\n")

X_raw = df.drop(columns=["Label"])
y_raw = df["Label"]

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
print(f"      After SMOTE – train : {X_train_res.shape[0]} "
      f"  {dict(zip(le.classes_, np.bincount(y_train_res)))}\n")

param_dist = {
    "n_estimators":      [100, 200, 300, 500],
    "max_depth":         [None, 10, 20, 30],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf":  [1, 2, 4],
    "max_features":      ["sqrt", "log2", 0.3],
    "class_weight":      ["balanced", None],
}

cv3 = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
search = RandomizedSearchCV(
    RandomForestClassifier(random_state=42, n_jobs=-1),
    param_dist, n_iter=20, scoring="f1_macro",
    cv=cv3, n_jobs=-1, random_state=42, verbose=1,
    return_train_score=True
)
search.fit(X_train_res, y_train_res)
print(f"\n      Best params : {search.best_params_}")
print(f"      Best CV F1  : {search.best_score_:.4f}\n")

best_params = search.best_params_

MAX_TREES    = best_params.get("n_estimators", 300)
oob_errors   = []
n_tree_range = list(range(10, MAX_TREES + 1, 10))

for n in n_tree_range:
    rf_oob = RandomForestClassifier(
        **{k: v for k, v in best_params.items() if k != "n_estimators"},
        n_estimators=n,
        oob_score=True,
        random_state=42,
        n_jobs=-1,
    )
    rf_oob.fit(X_train_res, y_train_res)
    oob_errors.append(1.0 - rf_oob.oob_score_)
    print(f"      n_trees = {n:4d}  |  OOB error = {oob_errors[-1]:.4f}")

best_rf = RandomForestClassifier(
    **best_params,
    oob_score=True,
    random_state=42,
    n_jobs=-1,
)
best_rf.fit(X_train_res, y_train_res)
print(f"      OOB accuracy (generalisation proxy) : {best_rf.oob_score_:.4f}")

cv5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_results = cross_validate(
    best_rf, X_train_res, y_train_res,
    cv=cv5,
    scoring={
        "accuracy":  "accuracy",
        "f1_macro":  "f1_macro",
        "roc_auc":   "roc_auc",
        "precision": "precision_macro",
        "recall":    "recall_macro",
    },
    return_train_score=True,
    n_jobs=-1,
)

print(f"\n  {'Metric':<20} {'Train mean':>12}  {'Train std':>10}  "
      f"{'CV mean':>10}  {'CV std':>8}  {'Gap':>6}  {'Status':>15}")
print("  " + "-" * 85)
for metric in ["accuracy", "f1_macro", "roc_auc", "precision", "recall"]:
    tr_mean = cv_results[f"train_{metric}"].mean()
    tr_std  = cv_results[f"train_{metric}"].std()
    cv_mean = cv_results[f"test_{metric}"].mean()
    cv_std  = cv_results[f"test_{metric}"].std()
    gap     = tr_mean - cv_mean
    flag    = "⚠ possible overfit" if gap > 0.05 else "✓ generalises well"
    print(f"  {metric:<20} {tr_mean:>12.4f}  {tr_std:>10.4f}  "
          f"{cv_mean:>10.4f}  {cv_std:>8.4f}  {gap:>6.3f}  {flag}")

train_sizes_abs, lc_train_scores, lc_val_scores = learning_curve(
    best_rf,
    X_train_res, y_train_res,
    cv=cv5,
    scoring="f1_macro",
    train_sizes=np.linspace(0.10, 1.0, 10),
    n_jobs=-1,
    shuffle=True,
    random_state=42,
)

lc_train_mean = lc_train_scores.mean(axis=1)
lc_train_std  = lc_train_scores.std(axis=1)
lc_val_mean   = lc_val_scores.mean(axis=1)
lc_val_std    = lc_val_scores.std(axis=1)

y_pred  = best_rf.predict(X_test)
y_proba = best_rf.predict_proba(X_test)[:, 1]

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
print(f"  OOB score         : {best_rf.oob_score_:.4f}")
print(f"{'='*50}\n")
print(classification_report(y_test, y_pred, target_names=le.classes_))

print("Saving individual plots …")
plt.rcParams.update({"font.size": 10, "axes.titlesize": 11})

metrics_labels = ["accuracy", "f1_macro", "roc_auc", "precision", "recall"]
train_means = [cv_results[f"train_{m}"].mean() for m in metrics_labels]
cv_means    = [cv_results[f"test_{m}"].mean()  for m in metrics_labels]
train_stds  = [cv_results[f"train_{m}"].std()  for m in metrics_labels]
cv_stds     = [cv_results[f"test_{m}"].std()   for m in metrics_labels]
cm          = confusion_matrix(y_test, y_pred)
fpr_arr, tpr_arr, _ = roc_curve(y_test, y_proba)

fig, ax = plt.subplots(figsize=(8, 4))
ax.plot(n_tree_range, oob_errors, color="steelblue", linewidth=2,
        marker="o", markersize=3, label="OOB error per step")
ax.axhline(1 - best_rf.oob_score_, color="red", linestyle="--",
           label=f"Final OOB error = {1 - best_rf.oob_score_:.4f}")
best_n = n_tree_range[np.argmin(oob_errors)]
ax.axvline(best_n, color="green", linestyle=":", alpha=0.7,
           label=f"Lowest OOB at n={best_n}")
ax.set_xlabel("Number of Trees")
ax.set_ylabel("OOB Error  (1 – OOB Accuracy)")
ax.set_title("Generalisation During Training – OOB Error vs n_estimators\n"
             "(Lower = better generalisation; converges when adding trees stops helping)")
ax.legend(); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/oob_error_curve.png", dpi=150)
plt.close()
print(f"  ✓  oob_error_curve.png")

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(train_sizes_abs, lc_train_mean, "o-", color="steelblue",
        label="Train F1 (macro)")
ax.fill_between(train_sizes_abs,
                lc_train_mean - lc_train_std,
                lc_train_mean + lc_train_std, alpha=0.15, color="steelblue")
ax.plot(train_sizes_abs, lc_val_mean, "s-", color="darkorange",
        label="CV F1 (macro)")
ax.fill_between(train_sizes_abs,
                lc_val_mean - lc_val_std,
                lc_val_mean + lc_val_std, alpha=0.15, color="darkorange")
gap = lc_train_mean[-1] - lc_val_mean[-1]
ax.annotate(f"Gap = {gap:.3f}\n({'overfit' if gap > 0.05 else 'OK'})",
            xy=(train_sizes_abs[-1], (lc_train_mean[-1] + lc_val_mean[-1]) / 2),
            xytext=(-100, 5), textcoords="offset points",
            arrowprops=dict(arrowstyle="->"), fontsize=9,
            color="red" if gap > 0.05 else "green")
ax.set_xlabel("Training Set Size")
ax.set_ylabel("F1-score (macro)")
ax.set_title("Learning Curve – Bias / Variance Analysis\n"
             "(Converging lines = good generalisation; large gap = overfit)")
ax.legend(); ax.set_ylim(0, 1.05); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/learning_curve.png", dpi=150)
plt.close()
print(f"  ✓  learning_curve.png")

fig, ax = plt.subplots(figsize=(9, 4))
x = np.arange(5)
bars_tr = ax.bar(x - 0.2, cv_results["train_f1_macro"], 0.4,
                 label="Train F1", color="steelblue", alpha=0.85)
bars_cv = ax.bar(x + 0.2, cv_results["test_f1_macro"],  0.4,
                 label="CV F1",    color="darkorange",   alpha=0.85)
for bar in list(bars_tr) + list(bars_cv):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.004,
            f"{bar.get_height():.3f}", ha="center", va="bottom", fontsize=8)
ax.set_xticks(x)
ax.set_xticklabels([f"Fold {i+1}" for i in range(5)])
ax.set_ylabel("F1-score (macro)")
ax.set_title("5-Fold CV – Train vs Validation F1 per Fold\n"
             "(Consistent bars across folds = stable generalisation)")
ax.set_ylim(0, 1.12); ax.legend(); ax.grid(True, axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/cv_fold_performance.png", dpi=150)
plt.close()
print(f"  ✓  cv_fold_performance.png")

x = np.arange(len(metrics_labels))
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(x - 0.2, train_means, 0.4, yerr=train_stds, capsize=4,
       label="Train", color="steelblue", alpha=0.85)
ax.bar(x + 0.2, cv_means,    0.4, yerr=cv_stds,    capsize=4,
       label="CV",    color="darkorange", alpha=0.85)
ax.set_xticks(x)
ax.set_xticklabels(["Accuracy", "F1 Macro", "ROC-AUC", "Precision", "Recall"])
ax.set_ylabel("Score")
ax.set_title("Train vs Cross-Validation Scores – Generalisation Summary\n"
             "(Δ = train−CV gap;  green Δ < 0.05 = good,  red Δ ≥ 0.05 = overfit)")
ax.set_ylim(0, 1.18); ax.legend(); ax.grid(True, axis="y", alpha=0.3)
for i, (tr, cv_) in enumerate(zip(train_means, cv_means)):
    gap_i = tr - cv_
    color = "red" if gap_i > 0.05 else "green"
    ax.text(i, max(tr, cv_) + 0.05, f"Δ{gap_i:.3f}",
            ha="center", fontsize=8, color=color, fontweight="bold")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/train_vs_cv_metrics.png", dpi=150)
plt.close()
print(f"  ✓  train_vs_cv_metrics.png")

fig, ax = plt.subplots(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=le.classes_, yticklabels=le.classes_, ax=ax)
ax.set_title("Random Forest – Confusion Matrix (Test Set)")
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/confusion_matrix.png", dpi=150)
plt.close()
print(f"  ✓  confusion_matrix.png")

fig, ax = plt.subplots(figsize=(6, 5))
ax.plot(fpr_arr, tpr_arr, color="steelblue", linewidth=2,
        label=f"ROC curve  (AUC = {auc:.4f})")
ax.plot([0, 1], [0, 1], "k--", linewidth=1, label="Random classifier")
ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
ax.set_title("Random Forest – ROC Curve (Test Set)")
ax.legend(); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/roc_curve.png", dpi=150)
plt.close()
print(f"  ✓  roc_curve.png")

importances = best_rf.feature_importances_
top20_idx   = np.argsort(importances)[-20:]
fig, ax = plt.subplots(figsize=(10, 6))
ax.barh(feat_names[top20_idx], importances[top20_idx], color="steelblue")
ax.set_title("Random Forest – Top 20 Feature Importances (MDI)")
ax.set_xlabel("Mean Decrease in Impurity")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/feature_importance.png", dpi=150)
plt.close()
print(f"  ✓  feature_importance.png")

print("\nBuilding generalisation dashboard …")
fig = plt.figure(figsize=(18, 11))
gs  = gridspec.GridSpec(2, 3, figure=fig, hspace=0.45, wspace=0.38)

ax0 = fig.add_subplot(gs[0, 0])
ax0.plot(n_tree_range, oob_errors, color="steelblue", linewidth=1.5,
         marker="o", markersize=2)
ax0.axhline(1 - best_rf.oob_score_, color="red", linestyle="--", linewidth=1)
ax0.axvline(best_n, color="green", linestyle=":", alpha=0.7)
ax0.set_xlabel("n_estimators"); ax0.set_ylabel("OOB Error")
ax0.set_title("OOB Error vs Trees\n(generalisation during training)")
ax0.grid(True, alpha=0.3)

ax1 = fig.add_subplot(gs[0, 1])
ax1.plot(train_sizes_abs, lc_train_mean, "o-", color="steelblue",
         linewidth=1.5, label="Train")
ax1.fill_between(train_sizes_abs,
                 lc_train_mean - lc_train_std,
                 lc_train_mean + lc_train_std, alpha=0.12, color="steelblue")
ax1.plot(train_sizes_abs, lc_val_mean, "s-", color="darkorange",
         linewidth=1.5, label="CV")
ax1.fill_between(train_sizes_abs,
                 lc_val_mean - lc_val_std,
                 lc_val_mean + lc_val_std, alpha=0.12, color="darkorange")
ax1.set_xlabel("Train size"); ax1.set_ylabel("F1 Macro")
ax1.set_title("Learning Curve\n(bias-variance)")
ax1.legend(fontsize=8); ax1.set_ylim(0, 1.05); ax1.grid(True, alpha=0.3)

ax2 = fig.add_subplot(gs[0, 2])
x   = np.arange(5)
ax2.bar(x - 0.2, cv_results["train_f1_macro"], 0.4,
        label="Train", color="steelblue", alpha=0.85)
ax2.bar(x + 0.2, cv_results["test_f1_macro"],  0.4,
        label="CV",    color="darkorange",   alpha=0.85)
ax2.set_xticks(x)
ax2.set_xticklabels([f"F{i+1}" for i in range(5)], fontsize=8)
ax2.set_ylabel("F1 Macro"); ax2.set_ylim(0, 1.12)
ax2.set_title("5-Fold CV F1 per Fold")
ax2.legend(fontsize=8); ax2.grid(True, axis="y", alpha=0.3)

ax3 = fig.add_subplot(gs[1, 0])
xi  = np.arange(len(metrics_labels))
ax3.bar(xi - 0.2, train_means, 0.4, yerr=train_stds, capsize=3,
        label="Train", color="steelblue", alpha=0.85)
ax3.bar(xi + 0.2, cv_means,    0.4, yerr=cv_stds,    capsize=3,
        label="CV",    color="darkorange", alpha=0.85)
ax3.set_xticks(xi)
ax3.set_xticklabels(["Acc", "F1", "AUC", "Prec", "Rec"], fontsize=8)
ax3.set_ylim(0, 1.18)
ax3.set_title("All Metrics: Train vs CV\n(Δ = gap; green < 0.05)")
ax3.legend(fontsize=8); ax3.grid(True, axis="y", alpha=0.3)
for i, (tr, cv_) in enumerate(zip(train_means, cv_means)):
    gap_i = tr - cv_
    color = "red" if gap_i > 0.05 else "green"
    ax3.text(i, max(tr, cv_) + 0.06, f"Δ{gap_i:.2f}",
             ha="center", fontsize=7, color=color, fontweight="bold")    

ax4 = fig.add_subplot(gs[1, 1])
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=le.classes_, yticklabels=le.classes_,
            ax=ax4, cbar=False, annot_kws={"size": 11})
ax4.set_title("Confusion Matrix\n(held-out test set)")
ax4.set_xlabel("Predicted"); ax4.set_ylabel("Actual")

ax5 = fig.add_subplot(gs[1, 2])
ax5.plot(fpr_arr, tpr_arr, color="steelblue", linewidth=2,
         label=f"AUC = {auc:.4f}")
ax5.plot([0, 1], [0, 1], "k--", linewidth=1)
ax5.set_xlabel("FPR"); ax5.set_ylabel("TPR")
ax5.set_title("ROC Curve (test set)")
ax5.legend(fontsize=9); ax5.grid(True, alpha=0.3)

fig.suptitle(
    "Random Forest – Generalisation Dashboard\n"
    f"OOB acc={best_rf.oob_score_:.4f}  |  CV F1={cv_results['test_f1_macro'].mean():.4f}"
    f"  |  Test F1={f1:.4f}  |  Test AUC={auc:.4f}",
    fontsize=12, fontweight="bold"
)
plt.savefig(f"{OUTPUT_DIR}/generalisation_dashboard.png", dpi=150, bbox_inches="tight")
plt.close()
print(f"  ✓  generalisation_dashboard.png")

joblib.dump(
    {"model": best_rf, "label_encoder": le, "variance_filter": vt},
    f"{OUTPUT_DIR}/rf_model.pkl"
)

cv_f1_mean = cv_results["test_f1_macro"].mean()
cv_f1_std  = cv_results["test_f1_macro"].std()
train_f1   = cv_results["train_f1_macro"].mean()
gap_final  = train_f1 - cv_f1_mean

print(f"\n{'='*60}")
print("  GENERALISATION SUMMARY")
print(f"{'='*60}")
print(f"  OOB accuracy   (unseen bootstrap bags)  : {best_rf.oob_score_:.4f}")
print(f"  CV  F1  mean ± std  (5-fold)            : {cv_f1_mean:.4f} ± {cv_f1_std:.4f}")
print(f"  Test F1  (held-out 20 %)                : {f1:.4f}")
print(f"  Test AUC (held-out 20 %)                : {auc:.4f}")
print(f"  Train F1 mean – CV F1 mean  (gap)       : {gap_final:.4f}  "
      f"{'✓ generalises well' if gap_final < 0.05 else '⚠ possible overfit'}")
print(f"{'='*60}")
print("\n✅  Random Forest training complete.")
print(f"\n  All outputs saved to: {OUTPUT_DIR}/")
for fname in sorted(os.listdir(OUTPUT_DIR)):
    print(f"    • {fname}")
