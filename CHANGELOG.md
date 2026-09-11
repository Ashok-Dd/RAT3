# Changelog

## 1.1.0+2

Bug-fix and hardening pass focused entirely on correctness — no new user-facing features.

### Fixed
- **Network tab showed nothing.** `TrafficStats` returns -1/unsupported on many modern devices;
  the native code was silently dropping every app with no usable reading, so the tab looked
  empty. Now reads real per-app bytes via `NetworkStatsManager` (falls back to `TrafficStats`
  only if that's unavailable), and the Network tab shows a tap-to-fix hint when usage-access
  permission isn't granted.
- **Duplicate OS notifications** for the same device-state condition (root / USB debugging).
  Two independent detectors (native `ScanForegroundService` and Dart `RuntimeMonitor`) each
  pushed their own notification with no shared dedup, and `RuntimeMonitor` additionally
  timestamped every alert's id uniquely, defeating the dedup that did exist. Alert ids are now
  stable per condition, and a new `AlertEvent.notify` flag lets one layer own the OS
  notification while the other still raises the alert in-app only.
- **Permission Tracker (Layer 3) didn't measure what it claimed to.** It alleged detecting a
  specific app misusing camera/mic/location, but only checked RAT3's own (irrelevant)
  permission grants plus a permission-agnostic usage count. Rewritten to use the native layer's
  real per-app sensor data, so alerts now name the actual app.

### Removed
- ~60 lines of dead "risk contribution" scoring code (`RuntimeMonitor`, `NetworkMonitor`,
  `PermissionTracker`) that was never called — the Dashboard's real score has only ever come
  from `FeatureCollector` → `RuleBasedScorer`.
- Dead heuristic `Layer4` config block left over from before the on-device ML ensemble.

### Changed
- `com.example.rat3` (self-package) is now one shared `AppConstants.selfPackageName` instead of
  three independent hardcoded copies.
- Release builds are minified (R8) and signed with a real upload keystore instead of the debug
  key; `targetSdk` bumped 35 → 36 to match `compileSdk`.

### Added
- Test coverage for the logic touched above: `test/alert_engine_test.dart`,
  `test/rule_based_scorer_test.dart`, and Kotlin `Layer1SafetyAnalyzerTest` /
  `Layer2PermissionMismatchTest` / `Layer3SignatureScannerTest` (via Robolectric).

## 1.0.0+1

Initial merge of the pre-installation APK scanner and post-installation device monitor into one
app, with a real on-device 4-model ML ensemble (Random Forest, Decision Tree, AdaBoost, XGBoost)
for the pre-install scanner's Layer 4.
