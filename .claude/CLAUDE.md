# RAT3 — Android Defensive Security Monitor

## Project Purpose

RAT3 is a **defensive Android security-monitoring and malware-detection application** —
one app, Flutter + Kotlin, `applicationId`/Kotlin package `com.example.rat3`, Android only.

It answers one question, in two halves:

> **Does this device show evidence of RAT (Remote Access Trojan) or spyware compromise —
> before or after an app gets installed?**

RAT3 is a security-analysis and detection tool. It is **not** a Remote Access Trojan and
must never implement RAT functionality.

```text
RAT functionality  ≠  RAT detection
```

RAT3 may detect, analyze, score, visualize, and explain RAT-like behavior. It must not
implement the behavior it is designed to detect. When a technical requirement can be
implemented in both an offensive and defensive way, implement the **defensive
detection/analysis version**.

---

# Security Boundary

All development in this repository must remain within a **defensive, authorized
security-monitoring scope**.

### Allowed

* Analyze applications installed on the user's own Android device.
* Inspect security-relevant metadata available through legitimate Android APIs.
* Monitor permitted network connection metadata (including via `VpnService`, purely to
  observe the device's own already-existing traffic — see the Network Tab section below).
* Correlate processes/UIDs with network activity where Android permits it.
* Detect suspicious behavioral patterns.
* Calculate malware/security risk scores.
* Identify potentially suspicious destinations.
* Detect repeated network connections and beacon-like timing patterns.
* Analyze permissions and application metadata.
* Display security alerts and explanations.
* Perform static or behavioral analysis for malware detection (including on-device ML).
* Generate defensive reports.
* Test detection logic using synthetic or benign test data.
* Improve detection accuracy using ML/statistical techniques.

### Not Allowed

* Remote control of another device.
* Unauthorized access.
* Credential theft.
* Keylogging.
* Screen spying.
* Hidden surveillance.
* Persistence mechanisms for malware.
* Privilege escalation.
* Exploitation of vulnerabilities against real targets.
* Command-and-control infrastructure.
* RAT payloads.
* Malware propagation.
* Evasion of antivirus/security monitoring.
* Stealth mechanisms intended to hide malicious activity.
* Data exfiltration.
* Covert collection of personal information.

If a requested implementation could cross this boundary, keep the implementation focused
on **detection, analysis, simulation, or safe testing**.

---

# Architecture: Two Independent Engines, One App Shell

RAT3 is genuinely **two separate security engines** with separate data, separate verdict
systems, and separate docs — sharing one app only for convenience. A file can pass the
pre-installation scan and still get flagged later by the post-installation monitor (or
vice versa).

| | Pre-Installation Scanner | Post-Installation Monitor |
|---|---|---|
| Question | "Is this `.apk` file safe to install?" | "Is anything on this live device behaving like a RAT right now?" |
| When it runs | You pick a file, or open one from a file manager / "Scan with RAT3" | Continuously, in the background, once turned on |
| Entry point | Scanner tab → "Scan an APK" mode | The whole 5-tab shell |
| Verdict system | SAFE / SUSPICIOUS / MALICIOUS (Decision Engine, 4 layers) | Dashboard 0–100 score (Risk Scoring Engine, 6 categories) + per-app Trust Engine verdicts |
| Full docs | [`docs/pre-installation/`](../docs/pre-installation/README.md) | [`docs/post-installation/`](../docs/post-installation/README.md) |

**`docs/` is the authoritative, human-readable spec for every feature** — written around
what the user sees and what it means, with worked examples and explicit honesty notes
about what's real vs. placeholder. Read the relevant doc page before changing detection
logic; update it when behavior changes. `docs/rat-behavior-coverage.md` is the single
honest matrix of real-world RAT behaviors vs. what RAT3 actually covers — check it before
claiming a detection gap is closed.

## App shell (Flutter, `lib/presentation/app_shell.dart`)

Five bottom-nav tabs: **Dashboard, Network, Alerts, Scanner, Settings**, plus a first-run
onboarding flow. Neon-cyber `AppTheme` (dark, neon green/red severity colors) throughout.

## Pre-Installation Scanner — 4 layers + Decision Engine

Kotlin, `android/app/src/main/kotlin/com/example/rat3/scanner/`. Each layer produces its
own 0–100 score + findings; the Decision Engine combines them.

| Layer | File | Weight | What it checks |
|---|---|---|---|
| 1 — App Safety | `Layer1SafetyAnalyzer.kt` | 20% | Manifest: dangerous/suspicious permissions, exported components, old target SDK, accessibility+overlay/admin/boot combo |
| 2 — Permission↔Function Match | `Layer2PermissionMismatch.kt` | 20% | Declared-but-unused sensitive permissions (low-confidence) + 4 always-dangerous APIs (`Runtime.exec`, `DexClassLoader`, `ProcessBuilder`, `ServerSocket`) |
| 3 — Signature & Reputation | `Layer3SignatureScanner.kt`, `Signatures.kt`, `Reputation.kt` | 35% | SHA-256 hash blocklist, named-family signature match, signing-cert repackaging check, obfuscation/native-lib/hardcoded-IP heuristics |
| 4 — ML Classifier | `Layer4MlClassifier.kt`, `ml/TuandromdFeatures.kt`, `ml/MlModels.kt` | 25% | On-device 4-model ensemble, see below |
| Decision Engine | `DecisionEngine.kt` | — | Weighted combine + escalation rules |

**Verdict bands:** 0–29 SAFE, 30–59 SUSPICIOUS, 60–100 MALICIOUS.

**Escalation (bypasses the weighted average):**
- Layer 3 hard hit (hash/signature match, or repackaging) → forces at least the escalation floor.
- Layer 4 ensemble reaches ≥3/4 models voting malware → same.
- **Single-layer alarm floor:** any one layer scoring ≥65 alone forces the verdict to at
  least SUSPICIOUS, even if the weighted average would land lower — prevents a lone strong
  signal (e.g. ML-only detection with nothing in Layers 1–3) from being averaged away.
- A layer that fails to complete analysis is capped low and can never alone push MALICIOUS.

### Layer 4 — ML ensemble (real on-device ML, not a heuristic)

Trained on **TUANDROMD** (4,465 labeled Android apps, 241 binary features: permission
presence, `activityCalled`, 28 dangerous-API DEX-string flags). `VarianceThreshold` narrows
to 199 features actually used at inference. Runs **4 models on-device**: Random Forest,
Decision Tree, AdaBoost (SAMME), XGBoost — majority vote on label + mean malware
probability → risk band (Safe/Low/Medium/High/Critical at 20/40/60/80). A 5th trained
model, **Stacking**, is intentionally **server-only** (`ml/app.py`) — its KNN base learner
needs the full fitted SMOTE-resampled training matrix, which can't be bundled compactly.
This is a documented scope limit, not an oversight (`ml/feature_schema.md`).

Models are exported from the trained sklearn/XGBoost `.pkl` files (`ml/models/`) via
`ml/export_models_for_android.py` into `android/app/src/main/assets/ml/*.json` (~700 KB).
**Parity is tested, not assumed**: `MlEnsembleParityTest.kt` checks Kotlin vs. Python
output on 42 real+synthetic vectors — last verified run: 168/168 predictions matched
within 2.5 points. Re-run this test after touching `MlModels.kt` or the exported JSON,
not just re-read the code, before claiming ML status.

## Post-Installation Monitor — 5 background layers + two scoring engines

Dart layers in `lib/layers/`, native persistence in
`android/app/src/main/kotlin/com/example/rat3/ScanForegroundService.kt`.

| Layer | File | Checks |
|---|---|---|
| 1 — Runtime Monitor | `runtime_monitor/runtime_monitor.dart` | CPU, memory, processes, root status (~15s) |
| 2 — Network Analyzer | `network_monitor/network_monitor.dart` | Per-app data-usage **deltas** (not cumulative totals — see below) + suspicious IP/port heuristic (~20s) |
| 3 — Permission Tracker | `permission_tracker/permission_tracker.dart` | Which *other* apps are actively using (mic: exact per-app match; camera: best-available) or have heavy background time with camera/mic/background-location |
| 4 — Alert Engine | `alert_engine/alert_engine.dart` | Dedup + routes every layer's findings into the Alerts tab (3-tier dedup: never repeat in-session, cooldown window across sources, fresh-start per full app scan) |
| 5 — Risk Engine | `risk_engine/risk_engine.dart`, `feature_engine/rule_based_scorer.dart` | Combines ~65 device signals into the Dashboard score |

**Two independent scanning paths, only one survives the app being closed:**
- **Native background service** (`ScanForegroundService.kt`) — narrow, focused checks
  (live camera/mic, background upload, root, risky sideloaded app, enabled accessibility
  service). Dual Handler+AlarmManager timers, wake lock, re-arms on failed cycles, restarts
  after reboot (`BootReceiver.kt`). This is what the auto-scan interval setting controls.
  Shares logic with `MainActivity` via `DeviceAppUtils.kt` (OEM-preload detection, device
  setup time, enabled-accessibility-services) — **do not let these two copies drift apart
  again**; that was a real, since-fixed bug (see CHANGELOG).
- **The 5 rich layers above + full Dashboard score** — run inside the app process, update
  ~1/min while open, do **not** persist if Android kills the process (OEM-dependent,
  e.g. Vivo is aggressive about this).

### App Trust Engine (`AppTrustEngine.kt`, `UserTrustStore.kt`) — "Scan All Apps"

Replaced an earlier version that scored ordinary permission-holding as risk (flagged
WhatsApp/PhonePe). Current design:

1. **OEM/carrier-preloaded apps are excluded from scanning entirely** — detected via
   install-timestamp clustering near first boot (~3 days), not a system-app flag (most
   preloads aren't `/system` apps).
2. **Trust baseline**: Play Store + not installed in the last 7 days + not holding
   accessibility+(overlay|admin|boot-autostart) → **TRUSTED**, full stop, regardless of
   permissions held or data sent.
3. Everything else goes through an **evidence ladder** (Weak / Medium=Private Data Access /
   Strong / Confirmed) → **UNKNOWN / NEEDS REVIEW / SUSPICIOUS / MALICIOUS INDICATORS**.
   Only a confirmed hash match escalates alone; everything else needs ≥2 signals at a tier
   (or 1 at Medium/Strong) to move up.
4. **"Trust this app"** (`UserTrustStore.kt`, surfaced in the **Trusted Apps** screen
   reachable from Scanner tab → Scan All Apps) is a user override — any app, skips full
   evaluation on future scans until un-trusted.
5. Actions available: **Open App Info**, **Uninstall** — RAT3 cannot force-stop or
   silently revoke another app's permissions without root/Device-Owner, so these hand off
   to the system UI rather than faking a capability Android doesn't grant.

Full evidence-ladder tiers and worked examples: `docs/post-installation/06-app-trust-engine.md`.

### Risk Scoring Engine (`rule_based_scorer.dart`) — Dashboard score

Rule-based (not ML) by design — every point is explainable. ~65 real-device signals across
6 categories, weighted, capped at 100 per category:

| Category | Weight |
|---|---|
| Sensor Behavior | 25% |
| Network & Resource | 25% |
| App Behavior | 20% |
| System Security | 15% |
| Permission Behavior | 10% |
| Aggregated Correlations (cross-signal, e.g. sensor+network same moment) | 5% |

**Dashboard bands:** 0–20 SAFE, 21–40 MONITOR, 41–60 SUSPICIOUS, 61–80 HIGH RISK,
81–100 CRITICAL. (Note: this is a **different** band system from the pre-install
scanner's SAFE/SUSPICIOUS/MALICIOUS — don't conflate the two when changing thresholds.)

**Rules removed/changed after being found to score bugs or ordinary configs as risk** —
don't reintroduce these without the same fix:
- Background data used to be scored from a **30-day cumulative total**, not a live delta —
  fired on nearly every scan. Now uses per-poll deltas (`deltaTx`), with a cold-start guard
  so the very first reading after install/reboot isn't misread as a burst.
- Sideloaded-app count alone is no longer scored (caught OEM preloads and dev builds);
  now only counts sideloaded apps *also* flagged NEEDS REVIEW+ by the Trust Engine.
- USB debugging / Developer Options alone are no longer scored; only root+USB-debugging
  together.
- Accessibility-service usage is scored once (App Behavior), not triple-counted across
  three categories.
- "Unique remote IPs" was actually counting unique package names (no real per-connection
  IP data exists outside the VPN monitor) — now reads 0 honestly when the VPN monitor is
  off, real data when it's on.
- Beacon-pattern rule compared a 30-day byte total to 1KB (never fired meaningfully) — now
  uses the VPN monitor's real reconnect data when active.

### Network Tab — two views

1. **Default (always on):** aggregate per-app bytes sent/received — explicitly
   supplementary context, not the headline feature.
2. **Real-Time Connection Monitor (opt-in, `RatVpnService.kt` + `ConnectionTracker.kt` +
   `TcpRelay.kt`/`UdpRelay.kt`/`IpPacket.kt`/`DnsParser.kt`):** genuine per-connection
   process/IP/port/protocol/duration visibility via a local relay-only `VpnService` —
   required because Android 10+ blocks reading other apps' connections any other way.
   Traffic is relayed to its real destination unchanged; nothing is rerouted or inspected
   for content. **Both IPv4 and IPv6** TCP/UDP are parsed, relayed, and tracked (`IpPacket.kt`'s
   shared `IpHeader` interface, version inferred from address length, correct 12-byte/
   40-byte pseudo-header checksum per RFC 8200) — but **the IPv6 path has not been
   verified against real IPv6 traffic on a physical device**, unlike the IPv4 path.
   Unit-tested and independently code-reviewed, not field-proven; say so if asked about its
   status. IPv6 packets using extension headers are out of scope (dropped, not misparsed).

   Connection assessment: **NORMAL** (default) / **NEEDS INVESTIGATION** (exactly 1 signal)
   / **SUSPICIOUS** (2+ signals). Signals: persistent/repeated reconnection to the same
   address, known-suspicious port (e.g. 1337/4444/31337), known-malicious IP range
   (illustrative bundled list, not a live feed), the owning app already flagged by the
   Trust Engine, or a DNS-query domain that looks algorithmically generated
   (`looksAlgorithmicallyGenerated()`, Dart — length + entropy/consonant-run, deliberately
   conservative since random-looking CDN/cloud subdomains are a known false-positive
   source; names only *that query's own* domain, not a NAT-level IP→domain correlation).

---

# Detection Philosophy

RAT3 should **never classify an application or connection as malware/suspicious from a
single weak indicator.** Every scoring system in this codebase is built around
**correlated combinations**, not single facts — this is the exact principle that both the
App Trust Engine rewrite and the Risk Engine bug-fix list above exist to enforce. Holding a
permission, sending data, or running in the background is never, by itself, evidence.

Every high-risk finding must explain **which specific signals fired together**, not just
show a bare severity — this is enforced throughout (`alert_engine.dart`'s findings,
`DecisionEngine.kt`'s summary text, App Trust Engine's per-app evidence list).

Prefer language like "Suspicious behavior detected," "Potentially malicious," "RAT-like
pattern," "Requires investigation" over declaring certainty ("This is definitely a RAT"),
unless the evidence is a confirmed hard hit (hash match, signature match, repackaging).

---

# Known Gaps — Be Honest, Don't Overstate Coverage

`docs/rat-behavior-coverage.md` is the authoritative matrix; check it before claiming
something is or isn't covered. As of this writing the once-open gaps below are **closed**
— don't re-report them as missing without re-checking the matrix and the actual code first:
screen-recording/clipboard detection (now wired into the Sensor Scan screen), silent
install/uninstall detection (both `REQUEST_INSTALL_PACKAGES` and `REQUEST_DELETE_PACKAGES`
are weak-tier App Trust Engine signals), keystroke-logging naming (the post-install
accessibility finding now says "keylogging" explicitly, matching the pre-install scanner),
contacts/call-log access (named findings, not just a generic tally), file exfiltration
(storage access + a real 50MB+ sent-data floor, correlated), hidden launcher icon, and
Play Protect status (now a weak System Security signal instead of read-and-dropped).

Genuine gaps that remain:
- **DNS-based C2 is only partially covered** — the connection monitor now extracts the
  domain from outbound DNS queries and applies a conservative DGA-style heuristic
  (`DnsParser.kt`, `looksAlgorithmicallyGenerated()`), but this names only *that query's
  own* domain. There is no NAT-level correlation from a later connection's resolved IP
  back to the domain that resolved it — a real, not yet closed, piece of this gap.
- **IPv6 support exists but is unverified on a real device.** The VPN relay parses,
  relays, and tracks IPv6 traffic with unit-tested, independently-reviewed packet logic —
  but unlike the real-device-tested IPv4 path, nobody has run this build against actual
  IPv6 network traffic. Don't present it with the same confidence as IPv4 when discussing
  status with the user. IPv6 extension headers are out of scope regardless (documented,
  not silently dropped-without-explanation).
- Traffic content inspection, silent screenshot capture, and DGA/anti-analysis evasion
  detection **in the pre-install static scan** are marked **not possible without root** —
  don't attempt to fake these.
- Bundled blocklists (file-hash, signature, malicious-IP, suspicious-port lists) are
  **illustrative placeholder data**, not a live threat-intel feed. The mechanism is real
  and correct; say so plainly rather than treating a placeholder-list miss as a detection
  failure.

---

# Build & Test

- **Kotlin unit tests:** `./gradlew :app:testDebugUnitTest` from `android/` — **not** the
  bare aggregate `gradlew test` (cross-drive C:/D: plugin-module config fails in this repo
  layout). Filter to ML parity: `--tests com.example.rat3.scanner.ml.*`.
- **Dart/Flutter tests:** `flutter test` from repo root (`test/alert_engine_test.dart`,
  `test/rule_based_scorer_test.dart`, etc.).
- **Build config notes:** Java 17, Kotlin 2.0.21, compileSdk 36, minSdk 24/targetSdk 35,
  multiDex + coreLibraryDesugaring on. `android/gradle.properties` intentionally sets
  `kotlin.incremental=false` and a low `-Xmx` — this host OOMs the Gradle daemon above
  ~4G, don't "fix" this by raising heap without checking host memory first.
- Test new detection logic against **both** benign scenarios (normal HTTPS browsing,
  periodic sync, push notifications, streaming, messaging) and synthetic suspicious
  patterns (regular beaconing, repeated reconnects, persistent connections, small
  periodic request/response, multiple unusual endpoints) — never by deploying an actual
  RAT-like payload.

---

# Android Platform Constraints

Never assume unrestricted access to Android internals. Before implementing monitoring
functionality, verify against: API-level restrictions, required permissions, sandbox
limitations, background-execution restrictions, UID/process visibility limits,
`VpnService` limitations, OEM-specific restrictions (this codebase has already hit
Vivo-specific background-kill and Android-14+ `BOOT_COMPLETED`+`dataSync` FGS crash
issues — see `BootReceiver.kt`), and battery/background limitations.

If Android does not expose a requested piece of information to a normal, non-rooted app,
**do not invent an API or pretend unrestricted monitoring is possible.** Follow the
pattern used throughout this codebase: read what's genuinely available, and when it isn't,
report the honest absence (e.g. "0 connections" when the VPN monitor is off) rather than a
fabricated stand-in — this is a recurring, deliberate design decision here, not an
oversight to "improve."

---

# Code Modification Guidelines

1. Read the relevant `docs/` page and the actual layer/engine file before changing
   architecture or scoring — this codebase has a documented history of the same class of
   bug (a stale cumulative number, a triple-counted signal, a missing OEM exclusion)
   recurring in more than one place; check `DeviceAppUtils.kt`-style shared-logic
   opportunities before duplicating a fix.
2. Preserve existing working functionality; prefer small, testable changes over rewrites.
3. Keep pre-install and post-install engines' data and verdicts separate — they are
   deliberately independent systems, not one shared pipeline.
4. Any new scoring rule must combine multiple signals (or be an explicit "confirmed hard
   hit" case like a hash match) — never a single ordinary permission/port/behavior alone.
5. Update the matching `docs/` page and, if it changes real coverage, `docs/rat-behavior-coverage.md`.
6. Re-run the ML parity test after touching `MlModels.kt`, `TuandromdFeatures.kt`, or the
   exported `assets/ml/*.json` — don't assume parity from reading code alone.
7. Avoid collecting unnecessary user data; keep analysis local (the ML classifier runs
   fully on-device with no network call by design — don't add one).
8. Do not introduce offensive security capabilities. When a feature is ambiguous,
   interpret it toward defensive monitoring and detection.
9. Re-run `IpPacketTest.kt`/`DnsParserTest.kt` after touching `IpPacket.kt`, `TcpRelay.kt`,
   `UdpRelay.kt`, `RatVpnService.kt`, or `DnsParser.kt` — a wrong checksum or a malformed
   header silently drops every relayed packet with no visible error, and this exact class
   of code has already produced a real, only-caught-by-review bug once (an IPv6 UDP
   checksum that could legally wire as the RFC-8200-invalid `0x0000`; see CHANGELOG). Any
   packet-relay code lacking real-device verification (currently: the whole IPv6 path)
   should be flagged as such when discussed, not presented with IPv4's confidence level.

---

# Output Requirements

When implementing or modifying RAT3, state: what changed, why, which Android APIs are
used, what telemetry is actually available (vs. what Android simply won't expose), what
detection signals are generated, how risk is calculated, how false positives are handled,
and how it was tested (unit test run, or manual scenario). Prefer transparent,
line-by-line-explainable scoring over opaque classifications — this is why the Risk
Scoring Engine is rule-based rather than ML, and why every escalation in the Decision
Engine names its specific trigger in the summary text.
