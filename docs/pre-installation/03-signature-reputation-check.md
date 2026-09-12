# Layer 3 — Signature & Reputation Check

## What it's for

This is the layer that looks for **confirmed** evidence, not just suspicious shape — known
malware fingerprints, tampered signing certificates, and classic malware-toolkit tells like
obfuscated payloads and hardcoded command-and-control addresses.

## What it actually looks at

### 1. File hash blocklist

Every APK file has a unique fingerprint (a SHA-256 hash). If that exact fingerprint
matches a hash on RAT3's known-malware list, this is treated as **confirmed** — this exact
file has been seen and identified as malicious before.

### 2. Signature patterns

A library of text/behavioral patterns tied to named malware families (for example, a
marker string associated with a known Android RAT toolkit, or a package name associated
with a known spyware family). A match names the specific family and is also treated as a
confirmed hit, not a guess.

### 3. Signing-certificate / repackaging check

Popular apps are normally signed by one specific, known certificate. If an APK claims to
be a well-known package name (say, a popular banking or messaging app) but is signed with
a *different* certificate than the real one, that's a strong sign the real app was taken
apart, modified, and repackaged under the same name — a classic trojanization technique.
A debug-signed APK (signed with the default developer test certificate rather than a real
release certificate) is also noted, though on its own this is common for sideloaded,
non-store apps and isn't treated as alarming by itself.

### 4. Obfuscation and payload-hiding heuristics

- **Large Base64-encoded blobs** in resources or assets — a common way to hide an
  encrypted or compressed secondary payload inside an otherwise innocent-looking file.
- **Suspicious native library names** (patterns associated with known hooking/injection
  tools) or native libraries placed in unusual locations (under `assets/` or `res/`
  instead of the normal library folder) — another payload-hiding trick.

### 5. Network indicators

- **Hardcoded IP:port addresses** in the app's text/resources — legitimate apps almost
  always use domain names, not raw IP addresses, for their servers.
- **`.onion` (Tor) addresses** — extremely rare in legitimate consumer apps.
- **Dynamic-DNS domains** (free hostname services often abused so a command-and-control
  server's address can change without updating the app) — flagged with a capped
  contribution if several appear.

## How it turns this into a score

Findings 1 and 2 (blocklist hash, signature match) and a repackaging mismatch are treated
as **hard hits** — confirmed evidence, not a probabilistic guess. A hard hit doesn't just
add points to this layer; it tells the [Decision Engine](05-final-verdict-engine.md) to
escalate the *overall* verdict regardless of what the other three layers found, because
this is the one layer capable of saying "this is a known bad file" rather than "this looks
risky."

The heuristic findings (obfuscation, native-library placement, network indicators) add
points normally, capped per category, and contribute to the layer's overall risk number
without forcing an escalation by themselves.

## Worked example

**A file whose hash matches a known malware sample** in the blocklist.
→ Hard hit. Regardless of what Layers 1, 2, and 4 say, the final verdict is forced to at
least the escalation floor — this alone is enough to push the app into MALICIOUS territory.

**An app claiming to be a popular banking app**, but the installed copy's signing
certificate doesn't match the certificate the real app is known to use, and the app also
contains three large Base64 blobs in its assets folder.
→ Repackaging mismatch (hard hit) plus the obfuscation finding stacking on top — a textbook
description of a phishing clone of a real banking app.

**An ordinary game APK downloaded from a third-party app store**, debug-signed (common for
apps distributed outside the Play Store), no blocklist match, no signature match, no
obfuscation, no network red flags.
→ Only the informational "debug-signed" note, worth a small number of points — nowhere near
the escalation floor.

## Honesty note

The bundled blocklist and trusted-certificate files that ship with RAT3 contain
**placeholder entries only** — they demonstrate the mechanism, not a live threat feed.
A real deployment would need to populate them from an actual threat-intelligence source
(commercial feed, a maintained open list, or your own confirmed samples). Until then, this
layer's *heuristic* checks (obfuscation, native libraries, network indicators) are what
actually run against everyday scans; the hash/signature hard-hit path is real and correct
code, just waiting on real data.
