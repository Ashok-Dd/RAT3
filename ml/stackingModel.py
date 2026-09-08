
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

from sklearn.model_selection   import (train_test_split, StratifiedKFold,
                                        GridSearchCV, learning_curve,
                                        cross_validate, cross_val_score)
from sklearn.preprocessing     import LabelEncoder, StandardScaler
from sklearn.ensemble          import (StackingClassifier, RandomForestClassifier,
                                        ExtraTreesClassifier)
from sklearn.linear_model      import LogisticRegression
from sklearn.neighbors         import KNeighborsClassifier
from sklearn.pipeline          import Pipeline
from sklearn.feature_selection import VarianceThreshold
from sklearn.metrics           import (accuracy_score, precision_score,
                                        recall_score, f1_score, roc_auc_score,
                                        matthews_corrcoef, confusion_matrix,
                                        classification_report, roc_curve)
from imblearn.over_sampling    import SMOTE
import joblib
import warnings
warnings.filterwarnings("ignore")

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("  ⚠ XGBoost not installed – will use GradientBoosting instead")
    from sklearn.ensemble import GradientBoostingClassifier

DATA_PATH  = "./Data/TUANDROMD.csv"
OUTPUT_DIR = "outputs/stacking"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 60)
print("  STACKING ENSEMBLE – Android Malware Detection")
print("=" * 60)
print("\n[1/8] Loading dataset …")
df = pd.read_csv(DATA_PATH)
print(f"      Shape              : {df.shape}")
print(f"      Class distribution :\n{df['Label'].value_counts()}\n")

X_raw = df.drop(columns=["Label"])
y_raw = df["Label"]

print("[2/8] Preprocessing …")

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

print("[3/8] Defining base learners …")

scaler = StandardScaler()

if HAS_XGB:
    neg, pos = np.bincount(y_train_res)
    xgb = XGBClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        scale_pos_weight=neg/pos,
        use_label_encoder=False, eval_metric="logloss",
        random_state=42, n_jobs=-1, tree_method="hist",
    )
else:
    from sklearn.ensemble import GradientBoostingClassifier
    xgb = GradientBoostingClassifier(n_estimators=200, max_depth=5,
                                     learning_rate=0.1, random_state=42)

base_learners = [
    ("random_forest", RandomForestClassifier(
        n_estimators=300, max_depth=20, class_weight="balanced",
        random_state=42, n_jobs=-1)),
    ("extra_trees", ExtraTreesClassifier(
        n_estimators=300, max_depth=20, class_weight="balanced",
        random_state=42, n_jobs=-1)),
    ("xgboost", xgb),
    ("logistic", Pipeline([
        ("scaler", StandardScaler()),
        ("lr", LogisticRegression(C=1.0, class_weight="balanced",
                                  max_iter=1000, random_state=42))
    ])),
    ("knn", Pipeline([
        ("scaler", StandardScaler()),
        ("knn", KNeighborsClassifier(n_neighbors=5, n_jobs=-1))
    ])),
]

for name, _ in base_learners:
    print(f"      Base learner: {name}")

print("\n[4/8] Cross-validating individual base learners …")
cv5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

base_cv_scores = {}
print(f"\n  {'Learner':<18} {'CV F1 Mean':>12}  {'CV F1 Std':>10}  {'CV AUC':>10}")
print("  " + "-"*55)
for name, estimator in base_learners:
    scores = cross_val_score(estimator, X_train_res, y_train_res,
                             cv=cv5, scoring="f1_macro", n_jobs=-1)
    auc_scores = cross_val_score(estimator, X_train_res, y_train_res,
                                 cv=cv5, scoring="roc_auc", n_jobs=-1)
    base_cv_scores[name] = {"f1_mean": scores.mean(), "f1_std": scores.std(),
                             "auc_mean": auc_scores.mean()}
    print(f"  {name:<18} {scores.mean():>12.4f}  {scores.std():>10.4f}  {auc_scores.mean():>10.4f}")

print("\n[5/8] Building Stacking model + tuning meta-learner …")

meta_param_grid = {"final_estimator__C": [0.01, 0.1, 0.5, 1.0, 5.0, 10.0]}

stack_base = StackingClassifier(
    estimators     = base_learners,
    final_estimator= LogisticRegression(max_iter=1000, random_state=42,
                                        class_weight="balanced"),
    cv             = StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
    passthrough    = False,
    n_jobs         = -1,
)

meta_search = GridSearchCV(
    stack_base, meta_param_grid,
    scoring="f1_macro", cv=cv5,
    n_jobs=-1, verbose=1,
    return_train_score=True,
)
meta_search.fit(X_train_res, y_train_res)

print(f"\n      Best meta C  : {meta_search.best_params_}")
print(f"      Best CV F1   : {meta_search.best_score_:.4f}\n")

best_stack = meta_search.best_estimator_

print("[6/8] Full stack 5-fold CV + learning curve …")

cv_results = cross_validate(
    best_stack, X_train_res, y_train_res,
    cv=cv5,
    scoring={"accuracy":"accuracy","f1_macro":"f1_macro",
             "roc_auc":"roc_auc","precision":"precision_macro",
             "recall":"recall_macro"},
    return_train_score=True, n_jobs=-1,
)

print(f"\n  {'Metric':<20} {'Train':>10}  {'CV':>10}  {'Gap':>8}  Status")
print("  " + "-"*60)
for m in ["accuracy","f1_macro","roc_auc","precision","recall"]:
    tr  = cv_results[f"train_{m}"].mean()
    cv_ = cv_results[f"test_{m}"].mean()
    gap = tr - cv_
    flag = "⚠ overfit" if gap > 0.05 else "✓ good"
    print(f"  {m:<20} {tr:>10.4f}  {cv_:>10.4f}  {gap:>8.4f}  {flag}")

print("\n  Computing learning curve (this may take a few minutes) …")
train_sz, lc_tr, lc_val = learning_curve(
    best_stack, X_train_res, y_train_res,
    cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=42),
    scoring="f1_macro",
    train_sizes=np.linspace(0.20, 1.0, 6),
    n_jobs=-1, shuffle=True, random_state=42,
)
lc_tr_mean  = lc_tr.mean(axis=1);  lc_tr_std  = lc_tr.std(axis=1)
lc_val_mean = lc_val.mean(axis=1); lc_val_std = lc_val.std(axis=1)

print("\n[7/8] Final evaluation on held-out test set …")
y_pred  = best_stack.predict(X_test)
y_proba = best_stack.predict_proba(X_test)[:, 1]

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

print("  Per-base-learner test scores:")
base_test_scores = {}
for name, est in best_stack.named_estimators_.items():
    try:
        bp  = est.predict(X_test)
        bpr = est.predict_proba(X_test)[:, 1]
        base_test_scores[name] = {
            "f1":  round(f1_score(y_test, bp, average="macro"), 4),
            "auc": round(roc_auc_score(y_test, bpr), 4),
        }
        print(f"    {name:<18}  F1={base_test_scores[name]['f1']:.4f}  AUC={base_test_scores[name]['auc']:.4f}")
    except Exception as e:
        print(f"    {name:<18}  Error: {e}")

print(f"    {'STACKING (full)':<18}  F1={f1:.4f}  AUC={auc:.4f}  ← ensemble")

print("\n[8/8] Saving plots …")
plt.rcParams.update({"font.size": 10, "axes.titlesize": 11})
cm = confusion_matrix(y_test, y_pred)
fpr_arr, tpr_arr, _ = roc_curve(y_test, y_proba)
metrics_labels = ["accuracy","f1_macro","roc_auc","precision","recall"]
tr_means = [cv_results[f"train_{m}"].mean() for m in metrics_labels]
cv_means_ = [cv_results[f"test_{m}"].mean()  for m in metrics_labels]
tr_stds  = [cv_results[f"train_{m}"].std()  for m in metrics_labels]
cv_stds  = [cv_results[f"test_{m}"].std()   for m in metrics_labels]

fig, axes = plt.subplots(1, 2, figsize=(13, 5))
learner_names = list(base_cv_scores.keys()) + ["STACKING"]
f1_means  = [base_cv_scores[n]["f1_mean"] for n in base_cv_scores] + [cv_results["test_f1_macro"].mean()]
f1_stds   = [base_cv_scores[n]["f1_std"]  for n in base_cv_scores] + [cv_results["test_f1_macro"].std()]
auc_means = [base_cv_scores[n]["auc_mean"] for n in base_cv_scores] + [cv_results["test_roc_auc"].mean()]
colors = ["steelblue","steelblue","steelblue","steelblue","steelblue","gold"]

ax = axes[0]
bars = ax.bar(learner_names, f1_means, yerr=f1_stds, capsize=5,
              color=colors, alpha=0.85, edgecolor="white")
ax.set_ylabel("F1 Macro"); ax.set_ylim(0, 1.12)
ax.set_title("Base Learners vs Stacking – CV F1")
ax.set_xticklabels(learner_names, rotation=20, ha="right", fontsize=8)
ax.grid(True, axis="y", alpha=0.3)
for bar, val in zip(bars, f1_means):
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.01,
            f"{val:.3f}", ha="center", fontsize=8)

ax = axes[1]
bars = ax.bar(learner_names, auc_means, color=colors, alpha=0.85, edgecolor="white")
ax.set_ylabel("ROC-AUC"); ax.set_ylim(0, 1.08)
ax.set_title("Base Learners vs Stacking – CV AUC")
ax.set_xticklabels(learner_names, rotation=20, ha="right", fontsize=8)
ax.grid(True, axis="y", alpha=0.3)
for bar, val in zip(bars, auc_means):
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.005,
            f"{val:.3f}", ha="center", fontsize=8)

plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/base_learner_comparison.png", dpi=150)
plt.close()
print(f"  ✓  base_learner_comparison.png")

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(train_sz, lc_tr_mean,  "o-", color="steelblue",  label="Train F1")
ax.fill_between(train_sz, lc_tr_mean-lc_tr_std, lc_tr_mean+lc_tr_std, alpha=0.12, color="steelblue")
ax.plot(train_sz, lc_val_mean, "s-", color="darkorange", label="CV F1")
ax.fill_between(train_sz, lc_val_mean-lc_val_std, lc_val_mean+lc_val_std, alpha=0.12, color="darkorange")
gap = lc_tr_mean[-1] - lc_val_mean[-1]
ax.annotate(f"Gap={gap:.3f}", xy=(train_sz[-1],(lc_tr_mean[-1]+lc_val_mean[-1])/2),
            xytext=(-90,5), textcoords="offset points",
            arrowprops=dict(arrowstyle="->"), fontsize=9,
            color="red" if gap>0.05 else "green")
ax.set_xlabel("Training Set Size"); ax.set_ylabel("F1 Macro")
ax.set_title("Stacking – Learning Curve (Bias-Variance)")
ax.legend(); ax.set_ylim(0,1.05); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/learning_curve.png", dpi=150)
plt.close()
print(f"  ✓  learning_curve.png")

fig, ax = plt.subplots(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=le.classes_, yticklabels=le.classes_, ax=ax)
ax.set_title("Stacking – Confusion Matrix (Test Set)")
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/confusion_matrix.png", dpi=150)
plt.close()
print(f"  ✓  confusion_matrix.png")

fig, ax = plt.subplots(figsize=(6, 5))
ax.plot(fpr_arr, tpr_arr, color="gold", lw=2.5, label=f"Stacking AUC={auc:.4f}")
colors_b = ["steelblue","seagreen","darkorange","mediumpurple","coral"]
for (nm, scores_), col in zip(base_test_scores.items(), colors_b):
    try:
        est = best_stack.named_estimators_[nm]
        fp, tp, _ = roc_curve(y_test, est.predict_proba(X_test)[:, 1])
        ax.plot(fp, tp, lw=1, linestyle="--", color=col,
                label=f"{nm} AUC={scores_['auc']:.4f}", alpha=0.75)
    except Exception:
        pass
ax.plot([0,1],[0,1],"k--",lw=1)
ax.set_xlabel("FPR"); ax.set_ylabel("TPR")
ax.set_title("Stacking vs Base Learners – ROC Curves")
ax.legend(fontsize=7); ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/roc_curves_comparison.png", dpi=150)
plt.close()
print(f"  ✓  roc_curves_comparison.png")

x = np.arange(len(metrics_labels))
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(x-0.2, tr_means,  0.4, yerr=tr_stds,  capsize=4, label="Train", color="steelblue",  alpha=0.85)
ax.bar(x+0.2, cv_means_, 0.4, yerr=cv_stds,  capsize=4, label="CV",    color="darkorange", alpha=0.85)
ax.set_xticks(x); ax.set_xticklabels(["Accuracy","F1 Macro","ROC-AUC","Precision","Recall"])
ax.set_ylim(0, 1.18); ax.set_ylabel("Score")
ax.set_title("Stacking – Train vs CV Generalisation")
ax.legend(); ax.grid(True, axis="y", alpha=0.3)
for i,(tr,cv) in enumerate(zip(tr_means,cv_means_)):
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
bars_ = ax0.bar(learner_names, f1_means, yerr=f1_stds, capsize=4,
                color=colors, alpha=0.85, edgecolor="white")
ax0.set_ylabel("CV F1 Macro"); ax0.set_ylim(0, 1.1)
ax0.set_title("Base Learners vs Stack")
ax0.set_xticklabels(learner_names, rotation=20, ha="right", fontsize=7)
ax0.grid(True, axis="y", alpha=0.3)

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
ax3.bar(xm-0.2, tr_means,  0.4, label="Train", color="steelblue",  alpha=0.85)
ax3.bar(xm+0.2, cv_means_, 0.4, label="CV",    color="darkorange", alpha=0.85)
ax3.set_xticks(xm); ax3.set_xticklabels(["Acc","F1","AUC","Prec","Rec"], fontsize=8)
ax3.set_ylim(0,1.18); ax3.set_title("All Metrics: Train vs CV")
ax3.legend(fontsize=8); ax3.grid(True, axis="y", alpha=0.3)

ax4 = fig.add_subplot(gs[1, 1])
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=le.classes_, yticklabels=le.classes_,
            ax=ax4, cbar=False, annot_kws={"size":11})
ax4.set_title("Confusion Matrix (Test)"); ax4.set_xlabel("Pred"); ax4.set_ylabel("Actual")

ax5 = fig.add_subplot(gs[1, 2])
ax5.plot(fpr_arr, tpr_arr, color="gold", lw=2.5, label=f"Stack AUC={auc:.4f}")
ax5.plot([0,1],[0,1],"k--",lw=1)
ax5.set_xlabel("FPR"); ax5.set_ylabel("TPR")
ax5.set_title("ROC Curve"); ax5.legend(fontsize=9); ax5.grid(True, alpha=0.3)

fig.suptitle(
    f"Stacking Ensemble – Generalisation Dashboard\n"
    f"CV F1={cv_results['test_f1_macro'].mean():.4f}  |  Test F1={f1:.4f}  |  Test AUC={auc:.4f}",
    fontsize=12, fontweight="bold"
)
plt.savefig(f"{OUTPUT_DIR}/generalisation_dashboard.png", dpi=150, bbox_inches="tight")
plt.close()
print(f"  ✓  generalisation_dashboard.png")

print("\nSaving model …")
joblib.dump(
    {"model": best_stack, "label_encoder": le, "variance_filter": vt},
    f"{OUTPUT_DIR}/stacking_model.pkl"
)

cv_f1_mean = cv_results["test_f1_macro"].mean()
cv_f1_std  = cv_results["test_f1_macro"].std()
train_f1   = cv_results["train_f1_macro"].mean()
gap_final  = train_f1 - cv_f1_mean

print(f"\n{'='*60}")
print("  GENERALISATION SUMMARY – STACKING ENSEMBLE")
print(f"{'='*60}")
print(f"  Base learners             : {[n for n,_ in base_learners]}")
print(f"  Meta-learner              : Logistic Regression (C={meta_search.best_params_['final_estimator__C']})")
print(f"  CV  F1  mean ± std        : {cv_f1_mean:.4f} ± {cv_f1_std:.4f}")
print(f"  Test F1  (held-out 20%)   : {f1:.4f}")
print(f"  Test AUC (held-out 20%)   : {auc:.4f}")
print(f"  Train–CV F1 gap           : {gap_final:.4f}  "
      f"{'✓ generalises well' if gap_final < 0.05 else '⚠ possible overfit'}")
print(f"{'='*60}")
print(f"\n✅  Stacking Ensemble training complete.")
print(f"\n  All outputs → {OUTPUT_DIR}/")
for f_name in sorted(os.listdir(OUTPUT_DIR)):
    print(f"    • {f_name}")