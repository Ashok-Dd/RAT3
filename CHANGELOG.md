# Changelog

## Unreleased

### Added (coverage breadth + engineering completeness pass)
- **App Trust Engine: six new evidence signals**, following the existing weak/medium-tier
  evidence-ladder pattern exactly (`AppTrustEngine.kt`, `MainActivity.kt`):
  - Silent uninstall (`REQUEST_DELETE_PACKAGES`, granted) — the uninstall-side companion
    to the existing silent-install signal.
  - Named contacts and call-log access, promoted from the generic dangerous-permission
    tally to their own Private Data Access findings, matching SMS/notifications.
  - A file-exfiltration correlation: broad storage/media access **and** a real (cumulative,
    not "just now" — see the honesty note in the code) sent-data floor, together.
  - No visible launcher icon/activity (`getLaunchIntentForPackage` returning null) — a
    common way an app hides itself after install.
  - The App Trust Engine's accessibility finding now names keylogging explicitly, matching
    the pre-installation scanner's existing wording, instead of only implying it.
- **Play Protect wiring**: `isVerifyAppsEnabled` was already read from the device but never
  used downstream. Now a low-severity System Security rule in the Risk Scoring Engine.
- **DNS query + domain-generation-algorithm (DGA) detection** in the VPN connection
  monitor: `DnsParser.kt` extracts the queried domain from outbound UDP:53 queries;
  `looksAlgorithmicallyGenerated()` (Dart) applies a conservative length+entropy/consonant-
  run heuristic as one more correlated signal in `ConnectionMonitor._assess` — deliberately
  weak-tier only, since random-looking CDN/cloud subdomains are a known false-positive
  source for this class of heuristic. Domain shown in the Network tab alongside the IP.
- **IPv6 support in the VPN relay** (`IpPacket.kt`, `RatVpnService.kt`, `TcpRelay.kt`,
  `UdpRelay.kt`, `ConnectionTracker.kt`): parses, relays, and tracks IPv6 TCP/UDP traffic
  using the same NAT/relay design as the existing IPv4 path — a common `IpHeader`
  interface lets `TcpRelay`/`UdpRelay` stay version-agnostic, `buildTcpPacket`/
  `buildUdpPacket` infer version from address length, and the TCP/UDP checksum now builds
  the correct pseudo-header for each (12-byte IPv4 vs. 40-byte IPv6 per RFC 8200). Unit
  tested at the packet level (parsing, building, checksum self-verification) but **not**
  verified against real IPv6 network traffic on a physical device — flagged explicitly as
  such in `docs/rat-behavior-coverage.md` and the Network tab docs, not presented with the
  same confidence as the real-device-tested IPv4 path. Packets using IPv6 extension headers
  are out of scope and dropped, not misparsed (documented in `IpPacket.kt`'s class comment).

### Fixed (self-review of the pass above, before it ever ran on a device)
An independent second read of the new VPN/IPv6/DNS/App Trust Engine code above, done
specifically because none of it had real-device verification to fall back on:
- **The file-exfiltration correlation's "sent network data" floor was set to 1MB** —
  trivially crossed by nearly any actively-used app within minutes, which would have made
  the two-signal correlation barely more selective than storage access alone, undermining
  the whole point of requiring both together. Raised to 50MB, matching this codebase's own
  established bar for "meaningful data volume" (the Risk Engine's existing "High Data
  Usage" rule) — caught before it ever ran on a device, not found live.
- **The new IPv6 UDP checksum could legally compute to the wire value `0x0000`** (~1-in-
  65536 chance per packet), which RFC 8200 §8.1 specifically forbids for IPv6 (unlike
  IPv4, where 0 means "unchecked") — a spec-compliant receiver would silently discard such
  a packet, indistinguishable from "the VPN doesn't work." Now substitutes `0xFFFF` per
  spec. Added a differential test (`IpPacketTest`) that searches 65536 payload variations
  and confirms the IPv6 checksum field is never observed as zero, while confirming the
  same search space *does* produce a zero IPv4 checksum at least once (proving the test
  actually exercises the target case rather than passing vacuously).
- **`DnsParser`'s "abort on binary garbage" guarantee had a gap**: it checked the
  *decoded* label string for non-printable characters, but `String(bytes, US_ASCII)`
  silently replaces any unmappable byte (0x80-0xFF) with `'?'` rather than failing —
  so a malformed/adversarial label containing raw binary could still produce a
  `'?'`-filled "domain" string instead of the documented `null`. Now checks the raw
  bytes before decoding. Added `DnsParserTest.kt` (11 tests) covering this and the
  parser's other defensive paths (compression pointers, truncated buffers, oversized
  labels, control characters, DNS responses vs. queries) — the parser had no dedicated
  test file before this.

### Fixed (full-app incomplete-feature audit — UI and functionality gaps)
- **Dashboard "Risk Breakdown" only showed 3 of the 6 weighted scoring categories** —
  Sensor Behavior (25%), App Behavior (20%), and Aggregated Correlations (5%), over half
  the score's total weight, were computed by `RuleBasedScorer`/`RiskEngine` but never
  rendered. Leftover from an in-progress rewrite that added the 3 new sub-scores to the
  engine but never touched `dashboard_screen.dart`. Now shows all six, correctly labeled
  (the one bar that was shown, "Runtime Behavior," is actually the System Security
  category — relabeled to match).
- **Cold-start "Open with → Scan with RAT3" could silently do nothing.** Native notifies
  Flutter of an incoming `.apk` intent synchronously during Flutter engine setup, often
  before `AppShell.initState()` has registered a handler to receive it — a `MethodChannel`
  call made before any handler exists is dropped, not queued. A pull-based fallback
  (`getInitialApkPath()`) already existed on both sides but was never called. `AppShell`
  now pulls it as a fallback, de-duplicated against the push path by APK path.
- **A genuine "Scan All Apps" failure was indistinguishable from "0 apps found."**
  `AppScannerService.runFullScan()` caught every exception internally and returned an
  empty-but-"successful" result, so `AppScanScreen`'s own error view was unreachable for
  a real scan failure. Now rethrows so the real error state is shown.
- **A real APK-picker failure looked identical to the user cancelling.** `pickApkFile()`
  swallowed `PlatformException` into a `null` return, the same value native sends for an
  intentional cancel. Now propagates the exception; the landing screen shows a snackbar
  for a real failure instead of silent nothing.
- **`getGrantedPermissions` always returned an empty list** — it AND'd the permission
  flags against `PackageManager.GET_PERMISSIONS` (a query flag) instead of
  `PackageInfo.REQUESTED_PERMISSION_GRANTED` (the actual grant bit). Unreachable from Dart
  today, but a real bug in working native code.
- **Silent app install/uninstall detection, dropped during the App Trust Engine rewrite
  (see `docs/rat-behavior-coverage.md`), is re-added** as a weak-tier evidence signal
  (`REQUEST_INSTALL_PACKAGES`, granted) — never escalates alone, since browsers and file
  managers legitimately hold it too.
- **Screen-recording and clipboard-access detection, built at the native layer but never
  called from any screen, are now wired into the Sensor Scan screen** alongside the
  existing mic/camera checks — real device-state reads, not permission tallies.
- Fixed an ML-classifier copy inconsistency: the scanning-progress screen said "5-model
  ensemble," contradicting both the docs and the landing screen's own "4-model ensemble"
  copy (only 4 of 5 trained models ship on-device — see
  `docs/pre-installation/04-ml-malware-classifier.md`).
- Removed the unused `ACCESS_WIFI_STATE` permission — no code path uses `WifiManager`.
- Documented (did not attempt to "fix" — it's a genuine Android platform limit, not a
  bug) that `ActivityManager.getRunningAppProcesses()` has been restricted to the calling
  app's own process since Android 5.1 for a normal app, so the Runtime Monitor's
  "Excessive Background Processes" rule can never realistically fire from real
  cross-app data on a modern device.

### Fixed (background scanner + Network Monitor — a second pass, prompted by
### "is auto-scan reliable, and is the network monitor correct")
- **The background scanner (`ScanForegroundService`) carried its own, independent copies of
  logic already fixed elsewhere, and had drifted out of sync.** It's a separate Kotlin
  implementation from `MainActivity`/`RuleBasedScorer` specifically so it can keep running
  when the app is fully closed (dual Handler+AlarmManager timers, wake locks, boot recovery
  — this scheduling design is solid and was verified correct). But because it duplicated
  detection logic instead of sharing it, three of yesterday's fixes never reached it:
  - USB debugging alone still pushed a HIGH "USB debugging enabled" notification,
    unconditionally — the exact false positive removed from the Dashboard yesterday. Now
    only fires (as "Rooted device with USB debugging enabled") when combined with root,
    matching the Dashboard's rule exactly.
  - Its sideloaded-app check (2+ risky permissions + no recorded installer) had no
    OEM-preload exclusion, so a factory-bundled app could still trigger a "Suspicious app"
    push notification. Now skips OEM/carrier-preloaded apps the same way Scan All Apps does.
  - Its accessibility check flagged any app that merely *declares*
    `BIND_ACCESSIBILITY_SERVICE` in its manifest — many legitimate apps (password managers,
    screen readers) do this without the user ever turning the service on. Now checks
    actually-ENABLED services via `AccessibilityManager`, not declared permissions.
  - **Root fix:** extracted the shared logic (`isOemPreinstalled`, `computeDeviceSetupTimeMs`,
    `getActiveAccessibilityServicePackages`) into a new `DeviceAppUtils.kt` object used by
    *both* `MainActivity` and `ScanForegroundService`, instead of leaving two independent
    copies that can silently drift apart again the next time either one is fixed.
- **"Unique remote IPs contacted" was actually counting unique app package names, not IP
  addresses.** `NetworkMonitor`'s always-on byte-counter path has no real per-connection IP
  data at all (`NetworkConnection.ipAddress` stores the package name there, by its own doc
  comment) — `TrafficStats`/`NetworkStatsManager` only report per-app totals. Found live: an
  "84 unique remote IPs contacted" alert that was really just 84 apps with any network
  activity in the last hour. Now uses the opt-in VPN connection monitor's real IP data when
  it's active, and honestly reports 0 — not a fabricated proxy — when it isn't.
- **"Frequent small packets" (the beacon-pattern rule) compared a 30-day cumulative byte
  total to 1KB**, which essentially never fires for any actively-used app — not a false
  alarm, but not real detection either, since the always-on path has no way to see repeated
  small connections, only per-app monthly totals. Now uses the VPN monitor's real
  per-connection reconnect data (`ConnectionEvidence.isPersistent`) when active; `false`
  (not a guess) when it isn't.

### Fixed (Dashboard risk score — genuine, evidence-based scoring)
- **The same 30-day-total-as-live-reading bug also existed independently in
  `NetworkMonitor`**, one layer over from the fix above — found live, via a fresh
  "Data sent during idle hours: 4110.8 MB" alert at 11:38 AM (nowhere near idle hours).
  `NetworkConnection.bytesSent` was set to the raw cumulative `txBytes` from
  `getAppNetworkUsage()`, and `_classifyApp`'s "high data usage → suspicious" rule and the
  "High Data Usage" alert both thresholded on that same cumulative figure — even though this
  monitor already computes a correct per-poll delta (`deltaTx`) for its "active upload"
  detection right next to the buggy code. Any app with normal historical usage (a browser,
  a messaging app) was permanently classified `suspicious` and permanently eligible for a
  "High Data Usage" alert, forever, regardless of anything happening right now. Both rules
  now use `deltaTx` (new bytes since the last ~20s poll). `dataSentDuringIdleMb` also no
  longer sums individual connections' cumulative `bytesSent` for a stale-timestamp-filtered
  subset — it reuses the already-delta-corrected total above, gated on whether the *current*
  scan is happening during idle hours.
- **`deltaTx` itself had a cold-start version of the exact same bug.** The very first
  reading for any app (no prior snapshot yet — e.g. right after RAT3 restarts) computed
  `deltaTx = txBytes - 0`, i.e. that app's entire 30-day total, and reported it as a burst
  that "just happened." Found live: a CRITICAL "Active Data Exfiltration Detected" alert
  claiming "Free Fire MAX is uploading 245.6 MB of data right now" seconds after a fresh
  install — that 245.6MB was its accumulated monthly total, not a live transfer. A missing
  baseline now scores a delta of 0, matching the guard already used for the whole-device
  total above, instead of implicitly treating "no history yet" as "zero before now."
- **Gboard was misclassified as "Suspicious Active Upload"** for a routine ~2MB background
  sync (dictionary/clipboard data) — found live. `NetworkMonitor`'s skip-list already
  exists specifically to exclude well-known Google/system packages from this kind of
  scrutiny; Gboard's package (`com.google.android.inputmethod.latin`) had simply never
  been added to it.
- **"Background data sent" was actually a 30-day, whole-device total, not a live reading.**
  `queryUidNetworkBytes` (native) sums `NetworkStatsManager` usage over the last 30 days
  across every installed app — a real, useful number for "how much data has this app used
  this month," but `FeatureCollector` was feeding that same value straight into the Network
  category's "data sent in the background" rules every single scan. On any actively-used
  phone, 30 days of total traffic is essentially always well past the 50MB "High" threshold,
  so this rule — and the "data sent without interaction" rule and the mic/camera+network
  correlation checks, which all reused the same number — fired on nearly every scan,
  regardless of anything the device was actually doing right then. `FeatureCollector` now
  tracks the previous reading and scores only the delta since the last scan, so these rules
  measure genuinely new activity instead of a permanently-inflated lifetime total. Confirmed
  live: this was the largest single contributor to an observed 71/100 score dropping toward
  a device-appropriate baseline after this and the App Behavior fix below.
- **App Behavior scored raw sideloaded/unknown-installer app counts as risk, not evidence.**
  "3+ apps installed outside Play Store" scored Critical regardless of whether any of those
  apps showed a single other concerning signal — meaning a phone that simply shipped with
  several OEM/carrier-bundled apps, or a developer with their own sideloaded test builds,
  was scored as if that alone were meaningful RAT evidence. Now scores only apps the App
  Trust Engine's own evidence ladder already flagged NEEDS REVIEW or worse (see
  `flaggedAppCount` below) — sideloaded *and* showing some other real signal, not sideloaded
  status alone.
- **USB debugging and Developer Options were scored as risk on their own.** Both are
  ordinary, common settings for developers and power users; a RAT's threat model is
  remote/network control, not local physical USB access. Neither is scored alone anymore —
  only the combination of root **and** USB debugging together is named, since that
  meaningfully widens local-access risk in a way neither setting implies by itself.
- **Accessibility-service usage was scored three separate times** across App Behavior,
  System Security, and Permission Abuse, for the exact same underlying fact — amplifying a
  single legitimate accessibility app (a screen reader, a password manager's autofill) far
  more than intended. Now scored once, in App Behavior.
- **Factory/carrier-preloaded apps are now excluded from scanning entirely** (see the App
  Trust Engine section below) — this is also what makes the App Behavior fix above
  effective; without it, a device's own bundled apps would still inflate `flaggedAppCount`
  indirectly by never having a fair chance to clear the evidence ladder as OEM software.

### Added
- **User-defined trusted apps.** Every app card in Scan All Apps now has a "Trust this app"
  action (`UserTrustStore.kt`, SharedPreferences-backed). Marking an app trusted is an
  explicit user override — separate from the automatic Play-Store baseline — that
  immediately sets it to TRUSTED and skips it entirely in every future scan (no AppOps
  calls, no APK hashing, no Permission Tracker naming), so RAT3's ongoing work stays
  focused on apps the user hasn't already vetted. A newly installed app is never on this
  list by default, so it always goes through the full evidence ladder until the user says
  otherwise.
- **Mitigation actions.** Flagged apps now have "Open App Info" (Force Stop / Uninstall /
  Permissions, one tap away) and, for Suspicious/Malicious Indicators, "Uninstall" —
  documented honestly as the real ceiling for what an unrooted, non-Device-Owner app can do:
  Android gives no API to force-stop another app's process or silently revoke its
  permissions, so these open the exact system screen instead of pretending to do it directly.
- **Exact real-time microphone attribution.** `checkMicInUse()` previously discarded the
  UID it already had from `AudioManager.getActiveRecordingConfigurations()` and returned
  only a yes/no boolean. It now exposes the actual recording UID(s)
  (`getActiveRecordingUids()`), so a microphone-in-use alert can name the exact app with
  certainty instead of listing every permission holder as an equally-likely "suspect".
  Camera has no equivalent per-UID API on Android, so camera attribution stays a best-effort
  candidate match — documented as such rather than implied to be as certain as mic.
- **Trusted Apps screen.** Scanner tab → a new full-screen list of every installed app with
  a search box and a per-app toggle switch, so trust status can be reviewed and changed for
  any app in one place instead of only from inside each app's own detail sheet.
- **Factory/carrier-preloaded apps are now excluded from scanning entirely** — not just
  capped at TRUSTED (`isOemPreinstalled()`, `MainActivity.kt`). Every app flashed as part of
  the original device image gets (almost) the exact same `firstInstallTime`, clustered at
  first boot; anything the user installs afterward gets a meaningfully later one. See the
  Dashboard scoring fixes above for the false-positive this directly caused.

### Fixed
- **Mic-in-use detection silently regressed to always-false.** `AudioRecordingConfiguration
  .getClientUid()` is a hidden/non-SDK method; some Android versions block reflective access
  to it entirely. The exact-attribution refactor above caught that failure with
  `catch { null }`, which silently dropped every session Android couldn't attribute — even
  though `activeRecordingConfigurations()` itself (a fully public, unrestricted API) still
  correctly reported that a recording was active. Confirmed live: logcat showed
  `activeRecordingConfigurations = 1 session(s)` immediately followed by `mic=false`. Split
  the yes/no check (`isAnyoneRecording`, now fails OPEN — assume active if it can't
  determine whose session it is, matching the already-working copy of this logic in
  `ScanForegroundService`) from the best-effort exact-UID attribution (`getActiveRecordingUids`,
  which still fails closed — names nobody rather than risk naming the wrong app).
- **Foreground-service blind spot in "is this app active right now".** `queryForegroundNowSet`
  (and the duplicate inline logic in `handleGetUserAppsUsingSensors`) only tracked Activity
  `MOVE_TO_FOREGROUND`/`MOVE_TO_BACKGROUND` events. An app whose Activity is closed and whose
  screen is locked, but whose foreground service is still recording — exactly the pattern a
  RAT uses to keep running after you've stopped looking at it — was invisible to this check,
  so `camActiveNow`/`micActiveNow` and the Permission Tracker's "actively using it now" tier
  could both silently miss a real, ongoing recording. Now also tracks
  `FOREGROUND_SERVICE_START`/`STOP` events over a 6-hour lookback (services can legitimately
  run for hours with no new event), so a still-running foreground service counts as active
  even with no open window.
- **Pre-installation `DecisionEngine` could average away a strong single-layer verdict.**
  Found via a real scan: Layer 4 (the ML ensemble) scored an APK 69/100, but the four layers'
  weighted fusion (L1×0.20 + L2×0.20 + L3×0.35 + L4×0.25) produced an overall score of 24 —
  SAFE — because Layers 1-3 saw nothing (no accessibility service, no overlay, no device admin,
  no blocklist hit) for an app whose RAT-like behavior is a network beacon and background
  persistence rather than accessibility abuse. Two fixes:
  - `Layer4MlClassifier`'s `hardHit` escalation trigger no longer requires a unanimous 4/4 ML
    vote — a confident 3/4 majority now also escalates, instead of getting averaged down by the
    other three layers.
  - `DecisionEngine` now has a general **single-layer-alarm floor**: any one layer scoring
    ≥65 on its own forces the overall verdict to at least SUSPICIOUS, regardless of what the
    weighted average says — mirroring the protection Layer 3's hard-hit already had, but no
    longer limited to signature/blocklist hits. Covered by new `DecisionEngineTest` cases using
    the exact 14/6/8/69 scores from the reported scan.

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
