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
| Screen recording / screen capture (MediaProjection) | 🟡 Partial | RAT3 can technically ask Android whether screen recording is active — the capability exists at the native layer — but nothing in the app currently calls it from any tab. It's built but disconnected, not surfaced anywhere a user would see it. |
| Silent app install/uninstall (installing or removing other apps without the user tapping through the system dialog) | ❌ Not covered | An earlier version of the app-scoring engine checked for this permission; the rewrite that fixed the WhatsApp/PhonePe false-positive problem (see the [App Trust Engine](post-installation/06-app-trust-engine.md)) dropped it and it was never re-added. A real gap, not a design choice. |
| Direct remote command execution (a live shell/C2 channel controlling the device in real time) | 🚫 Not possible directly | RAT3 cannot inspect another app's running code or its decrypted network traffic without root. What it *can* do is notice the pattern such control tends to produce — see the Network-level section below — which is indirect, correlational evidence, not proof of a live command channel. |

## 2. Surveillance & data collection

| Behavior | Status | Note |
|---|---|---|
| Reading SMS messages (OTP theft, 2FA interception) | ✅ Covered | A named Private Data Access finding. Calm and informational for a trusted app ("PhonePe can read SMS — used for OTP verification"), actual evidence for an untrusted one. |
| Reading notifications, including message/email previews from other apps | ✅ Covered | Checked via the notification-listener setting Android exposes to any app without a special permission — the real, detectable version of "can this app see my Gmail," since no Android API lets a third-party app read another app's actual Gmail data directly. |
| Reading on-screen content via accessibility (anything visible, including emails and chats being viewed) | ✅ Covered | Same tier as the two above; also double-counted deliberately as a distinct "screen control" capability where it overlaps with overlay abuse — explained in the Trust Engine doc's technical note. |
| Camera / microphone spying | ✅ Covered | Checked as genuine real-time hardware state (is it active *right now*), not just "holds the permission" — both as a Sensor Behavior signal on the Dashboard and as a strong App Trust Engine indicator for untrusted apps. |
| Background/continuous location tracking | ✅ Covered | Background-location access is both a weak/medium trust-engine indicator and a dedicated Sensor Behavior signal on the Dashboard. |
| Reading contacts or call logs | 🟡 Partial | These permissions are counted only inside a generic "how many dangerous permissions does this app hold" tally — unlike SMS, notifications, and screen content, they never get their own named "can read your contacts" or "can read your call log" finding. |
| Clipboard monitoring (stealing copied passwords, 2FA codes, crypto wallet addresses) | 🟡 Partial | Same situation as screen recording — a native capability to check clipboard-access activity exists, but no Dart feature or screen calls it. Built, not connected. |
| Keystroke logging via accessibility | 🟡 Partial | Explicitly named as a keylogging technique in the *pre-installation* scanner (checking an APK before install), but the *post-installation* App Trust Engine doesn't call this out as its own named finding — it's folded into the general accessibility-abuse indicators instead of stated by name. An inconsistency between the two engines, not a total gap. |
| File exfiltration (reading storage, then uploading it) | 🟡 Partial | Storage permission is counted generically; a matching network upload isn't correlated with it and named as "likely exfiltrating files" the way sensor activity + network activity is on the Dashboard. |
| Silent screenshot capture (without the recording indicator a user would notice) | 🚫 Not possible | Android doesn't expose a way for a third-party app — RAT3 included — to detect another app quietly taking screenshots without root. |

## 3. Persistence & evasion

| Behavior | Status | Note |
|---|---|---|
| Auto-starting on device boot | ✅ Covered | Holding boot-persistence permission is one of the factors in the App Trust Engine's trust-baseline check — an otherwise-trusted-looking app combining this with other capabilities loses its automatic pass. |
| Hiding its own launcher icon | 🟡 Partial | Whether an app has any visible activity at all is already read from the device and fed into the on-device ML classifier as one of its ~199 input features — but it never becomes its own plain-language finding like "this app hides its icon." It influences a score behind the scenes without being named. |
| Disabling or evading Google Play Protect | 🟡 Partial | Whether Play Protect's app-verification is turned on is read from the device, but that reading is never actually used anywhere afterward — not fed into the Dashboard's score, not shown as a finding. It's collected and then dropped. |
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
| DNS-based command-and-control (contacting algorithmically-generated domains, "domain generation algorithms") | ❌ Not covered | The connection monitor works at the IP level; it doesn't currently inspect or correlate DNS queries/resolved domain names. |
| Traffic content analysis (what's actually inside an encrypted connection) | 🚫 Not possible | RAT3 cannot decrypt HTTPS traffic without a TLS-intercepting proxy, which is a much larger, much more invasive undertaking than a connection monitor. Everything the Network tab knows about a connection is metadata — who, where, how often — never payload content. |
| IPv6 traffic | ❌ Not covered | The VPN engine is explicitly IPv4-only in this version; IPv6 packets are outside what it currently relays or inspects. Stated as a scope limit, not discovered silently. |
| Detecting an app that evades the VPN/routes around monitoring entirely | 🚫 Not possible | If something on the device could bypass RAT3's VPN capture outright, RAT3 has no independent vantage point left to notice that it happened. |

---

## Why some of these gaps exist and haven't been closed yet

- **The Private Data Access category (SMS, notifications, screen content) was deliberately
  scoped narrowly** to the things Android will actually tell any app without special
  privileges — extending the same treatment to contacts/call logs, clipboard, and file
  access is a natural next step, not a design rejection.
- **Screen-recording and clipboard detection exist at the native layer already** — the
  Kotlin methods behind them were built as part of this session's work and are exposed
  across the platform bridge, but nothing ever calls them from a screen or a monitoring
  layer. This is the cheapest gap to close of everything on this page, since the hard
  part (reading the signal from Android) is already done.
- **Silent-install detection was lost, not never-built** — it existed in the scoring
  engine that was replaced to fix the WhatsApp/PhonePe/Google Pay false-positive problem,
  and simply wasn't carried over into the rewritten App Trust Engine.
- **Everything marked "not possible" is a genuine Android platform limit**, not a gap in
  effort — matching the same policy the rest of these docs follow: state a limitation
  plainly rather than imply a false all-clear.
