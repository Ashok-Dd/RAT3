# RAT Malware Behavior Coverage

## What this document is

A single honest matrix: **every well-documented behavior real RAT (Remote Access Trojan)
and spyware families actually exhibit on Android, one row at a time, next to what RAT3
currently does about it.** This is not a marketing summary — it exists specifically to
write down the gaps, not just the wins, so the app's real coverage is never overstated
to anyone reading these docs, including the people building it.

It draws on the [pre-installation scanner](pre-installation/README.md), the
[post-installation monitor](post-installation/README.md) (especially the
[App Trust Engine](post-installation/06-app-trust-engine.md) and the
[Network tab](post-installation/02-network-tab.md)'s connection monitor), and the
[Risk Scoring Engine](post-installation/07-risk-scoring-engine.md).

## The four statuses used below

| Status | Meaning |
|---|---|
| ✅ **Covered** | An active, wired detection path exists and actually runs today. |
| 🟡 **Partial** | Something real exists, but it's incomplete in a specific, named way — see the note. |
| ❌ **Not covered** | RAT3 could plausibly check for this, but doesn't yet. |
| 🚫 **Not possible on Android** | No unrooted, non-system app — RAT3 included — can observe this at all. Stated plainly rather than implied as a silent gap. |

---

## 1. Remote access & control

| Behavior | Status | Note |
|---|---|---|
| Accessibility-service based remote control (reading the screen, simulating taps/gestures) | ✅ Covered | A strong indicator in the App Trust Engine on its own for an untrusted app; combined with an overlay permission it's treated as a confirmed persistence/control pattern. |
| Overlay-based screen takeover (drawing over other apps, fake buttons/screens) | ✅ Covered | Same engine — accessibility + draw-over-other-apps together is explicitly named as "a classic RAT/banking-trojan pattern." |
| Device Administrator abuse (block uninstall, force lock, wipe, password reset) | ✅ Covered | Holding Device Admin rights is a strong indicator by itself for an untrusted app, and disqualifies an app from the automatic "trusted" fast-path even if it's from the Play Store. |
| Screen recording / screen capture (MediaProjection) | ✅ Covered | Surfaced on the Sensor Scan screen alongside the mic/camera checks — a real device-state read (Android 14+ MediaProjection API, plus known-recorder-app and capture-permission heuristics on older versions), not a permission-holder guess. |
| Silent app install/uninstall (installing or removing other apps without the user tapping through the system dialog) | ✅ Covered | Re-added to the App Trust Engine as weak-tier evidence signals on untrusted apps — `REQUEST_INSTALL_PACKAGES` for the install side, `REQUEST_DELETE_PACKAGES` (silently removing apps it installed itself, no confirmation dialog) for the uninstall side. Both never escalate alone, since browsers, file managers, and app stores legitimately hold these too. |
| Direct remote command execution (a live shell/C2 channel controlling the device in real time) | 🚫 Not possible directly | RAT3 cannot inspect another app's running code or its decrypted network traffic without root. What it *can* do is notice the pattern such control tends to produce — see the Network-level section below — which is indirect, correlational evidence, not proof of a live command channel. |

## 2. Surveillance & data collection

| Behavior | Status | Note |
|---|---|---|
| Reading SMS messages (OTP theft, 2FA interception) | ✅ Covered | A named Private Data Access finding. Calm and informational for a trusted app ("PhonePe can read SMS — used for OTP verification"), actual evidence for an untrusted one. |
| Reading notifications, including message/email previews from other apps | ✅ Covered | Checked via the notification-listener setting Android exposes to any app without a special permission — the real, detectable version of "can this app see my Gmail," since no Android API lets a third-party app read another app's actual Gmail data directly. |
| Reading on-screen content via accessibility (anything visible, including emails and chats being viewed) | ✅ Covered | Same tier as the two above; also double-counted deliberately as a distinct "screen control" capability where it overlaps with overlay abuse — explained in the Trust Engine doc's technical note. |
| Camera / microphone spying | ✅ Covered | Checked as genuine real-time hardware state (is it active *right now*), not just "holds the permission" — both as a Sensor Behavior signal on the Dashboard and as a strong App Trust Engine indicator for untrusted apps. |
| Background/continuous location tracking | ✅ Covered | Background-location access is both a weak/medium trust-engine indicator and a dedicated Sensor Behavior signal on the Dashboard. |
| Reading contacts or call logs | ✅ Covered | Each now gets its own named Private Data Access finding ("Can read your contacts" / "Can read your call log"), the same tier and treatment as SMS and notifications. |
| Clipboard monitoring (stealing copied passwords, 2FA codes, crypto wallet addresses) | ✅ Covered | Surfaced on the Sensor Scan screen: lists background apps holding a capability (input-method or accessibility service) that can read clipboard content. Holding the capability isn't proof of misuse — shown as a "who could" list, not an accusation. |
| Keystroke logging via accessibility | ✅ Covered | The post-installation App Trust Engine's accessibility finding now names keylogging explicitly, matching the pre-installation scanner's wording, instead of only implying it through generic accessibility-abuse language. |
| File exfiltration (reading storage, then uploading it) | ✅ Covered | The App Trust Engine now correlates broad storage/media access with a real (cumulative, not "just now") sent-data floor into a named finding — worded as "has sent data," not "is exfiltrating," consistent with the project's rule against reading a cumulative TrafficStats number as a live claim. |
| Silent screenshot capture (without the recording indicator a user would notice) | 🚫 Not possible | Android doesn't expose a way for a third-party app — RAT3 included — to detect another app quietly taking screenshots without root. |

## 3. Persistence & evasion

| Behavior | Status | Note |
|---|---|---|
| Auto-starting on device boot | ✅ Covered | Holding boot-persistence permission is one of the factors in the App Trust Engine's trust-baseline check — an otherwise-trusted-looking app combining this with other capabilities loses its automatic pass. |
| Hiding its own launcher icon | ✅ Covered | Post-install, checked directly (`PackageManager.getLaunchIntentForPackage` returning null) and surfaced as its own named App Trust Engine finding on untrusted apps — separate from the pre-install ML classifier's `activityCalled` feature, which judges an APK before install and still influences that score behind the scenes without being named. |
| Disabling or evading Google Play Protect | ✅ Covered | Now wired into the Risk Scoring Engine as a low-severity System Security signal, instead of being read and dropped. |
| Dynamic code loading after install (fetching and running new code the installed APK didn't originally contain) | ❌ Not covered post-install | The *pre-installation* scanner does check an APK's code for dynamic-loading calls before you ever install it. Once an app is running, RAT3 has no way to observe it loading new code at runtime without root, and nothing currently tries. |
| Anti-analysis tricks (detecting it's being inspected, an emulator, or a debugger, and hiding behavior in response) | 🚫 Not possible | This only matters to the *pre-installation* static scan, and even there, RAT3 has no dynamic/behavioral sandbox — it can't run the APK to see if it behaves differently under observation. Out of scope for what a static, on-device scan can ever do. |
| Root/su abuse by an installed app specifically (as opposed to the device simply being rooted) | 🟡 Partial | Whether *the device itself* is rooted is a real, named Dashboard signal. Whether *a specific app* is the one using that root access is not attributable — RAT3 has no way to see which app issued a root command without being root itself. |

## 4. Financial-fraud-specific behavior

| Behavior | Status | Note |
|---|---|---|
| Fake banking login overlays drawn over the real app | ✅ Covered | The same accessibility + overlay combination described above, named explicitly as a banking-trojan pattern. |
| SMS-based OTP interception for fraudulent transactions | ✅ Covered | Same SMS finding as above, with the untrusted-install correlation making it a review/suspicious signal rather than a routine one. |
| Auto-confirming fraudulent transactions via accessibility (silently tapping "confirm payment" on the user's behalf) | 🟡 Partial | Covered only as part of the general accessibility-abuse strong indicator — there's no distinct, separately-named "automated transaction confirmation" finding calling this specific technique out by name. |
| Fake or cloned banking apps (repackaged with a different signature) | ✅ Covered | This is what the *pre-installation* scanner's signature/reputation layer exists for — checked before the app is ever installed. |

## 5. C2 communication & network-level behavior

This is what the [Network tab](post-installation/02-network-tab.md)'s opt-in VPN-based
connection monitor and the Dashboard's Network & Resource signals are for.

| Behavior | Status | Note |
|---|---|---|
| Persistent or repeated connections to the same remote host over time | ✅ Covered | The connection monitor's core correlation signal — a connection only gets flagged once it's been observed repeatedly across multiple polls, not on a single sighting. |
| Contact with a known-malicious IP address | ✅ Covered | Checked against a bundled list — same honesty caveat as the pre-install blocklist: the mechanism is real, the list itself is illustrative rather than a live threat-intel feed. |
| Use of suspicious/unusual ports | ✅ Covered | A bundled list of ports associated with known malware families. |
| Beaconing pattern (many small, evenly-spaced packets — a heartbeat to a C2 server) | ✅ Covered | A dedicated Network & Resource rule on the Dashboard. |
| Unusual data volume, especially during idle hours or in the background | ✅ Covered | Multiple named Dashboard rules, and one of the two halves of the Dashboard's flagship "sensor activity + network upload at the same moment" correlation rule. |
| Real per-connection IP, port, protocol, and owning-app identification | ✅ Covered | This is the entire point of the VPN engine — genuine per-connection visibility via Android's connection-ownership API, not a data-usage estimate. Opt-in, off by default, since it requires the system VPN consent dialog. |
| DNS-based command-and-control (contacting algorithmically-generated domains, "domain generation algorithms") | 🟡 Partial | The connection monitor now parses the queried domain out of outbound DNS (UDP:53) queries and applies a conservative DGA-style heuristic (label length + character entropy / consonant runs) as one weak signal among several — it names *this query's own* domain, not a NAT-level correlation from a later connection's IP back to the domain that resolved it, which remains out of scope. Deliberately conservative (requires both unusual length and unusual entropy) since random-looking subdomains are also routine on legitimate CDN/cloud infrastructure. |
| Traffic content analysis (what's actually inside an encrypted connection) | 🚫 Not possible | RAT3 cannot decrypt HTTPS traffic without a TLS-intercepting proxy, which is a much larger, much more invasive undertaking than a connection monitor. Everything the Network tab knows about a connection is metadata — who, where, how often — never payload content. |
| IPv6 traffic | 🟡 Partial | The VPN engine now parses, relays, and tracks IPv6 TCP/UDP traffic (fixed 40-byte header only — packets using IPv6 extension headers are not specially handled). The packet-level logic is unit-tested (header parsing, building, and checksum correctness), but unlike the IPv4 path — verified against real heavy browsing on a physical device — the IPv6 path has **not** been verified against real IPv6 network traffic on a device. Treat it as implemented-but-unverified, not production-proven, until that verification happens. |
| Detecting an app that evades the VPN/routes around monitoring entirely | 🚫 Not possible | If something on the device could bypass RAT3's VPN capture outright, RAT3 has no independent vantage point left to notice that it happened. |

---

## Why some of these gaps exist and haven't been closed yet

- **The Private Data Access category started narrowly scoped, then grew.** It originally
  covered only the things Android will tell any app without special privileges (SMS,
  notifications, screen content); contacts, call logs, clipboard, screen recording, and a
  correlated file-exfiltration signal have all since been added following the same pattern.
- **Silent-install detection was lost, then re-added — and its uninstall-side companion
  added alongside it.** The install-side check existed in the scoring engine that was
  replaced to fix the WhatsApp/PhonePe/Google Pay false-positive problem, wasn't carried
  over into the rewritten App Trust Engine, and has since been re-added as a weak-tier
  evidence signal, together with a matching `REQUEST_DELETE_PACKAGES` check it never had
  before.
- **DNS/domain visibility and IPv6 support are new, and asymmetrically verified.** The DGA
  heuristic and the App Trust Engine additions above are ordinary logic changes, tested the
  same way the rest of this codebase is (`flutter test` / `./gradlew testDebugUnitTest`).
  The IPv6 packet-relay path is different: it's unit-tested at the packet level (header
  parsing, building, checksum correctness) but has not been exercised against real IPv6
  network traffic on a physical device the way the IPv4 relay was. Flagged explicitly in
  its own row above rather than presented with the same confidence as the rest of this page.
- **Everything marked "not possible" is a genuine Android platform limit**, not a gap in
  effort — matching the same policy the rest of these docs follow: state a limitation
  plainly rather than imply a false all-clear.
