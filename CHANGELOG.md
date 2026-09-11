# Changelog

## 1.2.0+3

A full redirection of the post-install monitor onto RAT-specific evidence, away from generic
"phone manager" behavior — prompted by a real bug report: WhatsApp, PhonePe, Google Pay, and
YouTube were being flagged SUSPICIOUS/MALICIOUS by the "Scan All Apps" feature.

### Fixed
- **The reported bug.** `handleScanAllApps` computed a per-app score by adding points for
  holding permissions and doing normal background/network activity — any messaging, payment, or
  streaming app could trivially cross the "MALICIOUS" threshold just by existing. Replaced with
  `AppTrustEngine.kt`: a Play-Store-installed, established app with no accessibility+overlay/
  admin/persistence combination is always TRUSTED, regardless of permission count or activity.
  Regression-tested directly (`AppTrustEngineTest.kt`) against WhatsApp/PhonePe/Google Pay/
  YouTube-shaped fixtures.
- **Permission Tracker** no longer alerts on an established Play-Store app's own camera/mic use
  or background sensor access — it now needs the same "not from Play Store, or recently
  installed" correlation factor as Scan All Apps.
- **Network tab showed nothing real.** `/proc/net/tcp` is blocked by SELinux for third-party
  apps on Android 10+; the tab's only living data source was a byte-usage counter with the port
  hardcoded to 0. Added a real, opt-in connection monitor via a local VPN
  (`RatVpnService.kt` + `ConnectivityManager.getConnectionOwnerUid`) showing actual per-process
  remote IP/port/protocol/persistence.

### Added
- **Private Data Access** detection: which apps can read SMS, read notifications (via
  `Settings.Secure.enabled_notification_listeners`), or read on-screen content via accessibility
  — shown calmly (trusted apps: informational; untrusted apps: evidence), never as a scare.
  RAT3 had no detection at all for this before.
- Device Security Status expanded from 3 tiers (SAFE/WARNING/DANGER) to 5
  (SAFE/MONITOR/SUSPICIOUS/HIGH RISK/CRITICAL) so a single signal doesn't read the same as
  several correlated strong ones.
- A calm, evidence-first Dashboard summary ("No strong indicators... within what RAT3 can
  inspect") replacing the bare score.
- Real-time connection monitor (Network tab, off by default): per-connection process/remote-IP/
  port/protocol/duration/frequency, correlated the same way as the App Trust Engine — a single
  ordinary connection is never flagged.

### Removed
- The old per-app `AppRiskLevel`/`riskSignals`/`riskScore` wire format (replaced by
  `AppTrustLevel`/`evidence`/`trustReason`) and dead `RiskScore.computedLevel`.

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
