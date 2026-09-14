# Pre-Installation Scanner

## What it's for

You have an `.apk` file — downloaded from somewhere other than Google Play, shared by a
friend, sent over WhatsApp, sitting in a "Downloads" folder — and before you tap Install,
you want a straight answer: **is this safe to put on my phone?**

The pre-installation scanner reads the file itself (it is never installed to get scanned)
and gives you one of three verdicts: **SAFE**, **SUSPICIOUS**, or **MALICIOUS** — along
with the specific reasons behind that verdict, in plain language.

## How you start a scan

There are three ways to get a file into the scanner:

1. **From inside RAT3** — the Scanner tab has a *Scan an APK* mode with a file picker.
2. **From your file manager** — "Open with… RAT3" (or "Scan with RAT3") appears as an
   option whenever you tap an `.apk` file anywhere on the device.
3. **From a share/download flow** — some apps let you hand a downloaded file straight to
   another app; RAT3 registers itself as one of the options for `.apk` files.

In every case the flow is the same: RAT3 copies the file into its own private storage,
analyzes it there, and only then optionally hands it to Android's normal installer if you
choose to proceed. **RAT3 never installs anything on its own or without you explicitly
tapping through the system's own install prompt.**

## What actually happens during a scan

The file goes through **four independent layers**, each looking at a different aspect of
the APK, plus a **Decision Engine** that combines their findings into one final verdict.

```
   .apk file
       │
       ▼
┌──────────────────┐
│  Layer 1          │  Manifest & permissions
│  App Safety       │  → dangerous permissions, exported components,
│                    │    accessibility-service abuse, device-admin
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  Layer 2          │  Code vs. permissions
│  Permission↔      │  → does the code actually use what it asked for?
│  Function Match   │    + a short list of always-dangerous API calls
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  Layer 3          │  Signatures & reputation
│  Signature Check  │  → known-malware file hash, text signatures,
│                    │    repackaging/signing check, obfuscation, C2 hints
└──────────────────┘
       │
       ▼
┌──────────────────┐
│  Layer 4          │  Machine learning
│  ML Classifier    │  → 4-model ensemble trained on 4,465 real
│                    │    malware/goodware samples
└──────────────────┘
       │
       ▼
┌──────────────────┐
│ Decision Engine    │  Weighs all four layers, applies escalation
│                    │  rules, produces ONE final verdict
└──────────────────┘
       │
       ▼
   SAFE / SUSPICIOUS / MALICIOUS
```

Each layer runs independently and produces its own 0–100 risk score plus a list of
human-readable findings ("Declares 34 permissions — unusually large set", "Accessibility
service can read on-screen content of every app", etc.). Nothing is hidden — the results
screen shows every layer's findings, not just the final number.

## The three verdicts

| Verdict | What it means | What to do |
|---|---|---|
| **SAFE** | No layer found anything that matches how real malware behaves. | Installing is reasonable, same as any app from an unfamiliar source. |
| **SUSPICIOUS** | Some signals worth a second look, but nothing conclusive. | Read the specific findings before deciding — this is a "look closer," not a "don't install." |
| **MALICIOUS** | Either a confirmed hit (known-malware file hash, a matched malware signature, or a unanimous ML verdict) or several strong signals stacked together. | Installation is actively discouraged. |

## Pages in this section

- [Layer 1 — App Safety Analysis](01-app-safety-analysis.md)
- [Layer 2 — Permission ↔ Function Match](02-permission-code-match.md)
- [Layer 3 — Signature & Reputation Check](03-signature-reputation-check.md)
- [Layer 4 — ML Malware Classifier](04-ml-malware-classifier.md) *(the machine-learning core)*
- [Decision Engine — the final verdict](05-final-verdict-engine.md)

## What this scanner cannot do

Being upfront about limits is part of how RAT3 is built:

- It cannot detect a threat that **only appears after installation** — dynamic
  behavior that only shows up once the app is actually running, granted permissions,
  and talking to a live server. That's what the [post-installation monitor](../post-installation/README.md)
  is for.
- It cannot decrypt or fully reverse-engineer heavily obfuscated code — the code-level
  checks (Layer 2, Layer 3) work off text patterns and known signatures, not a full
  decompilation.
- The bundled malware-signature and file-hash lists are small, illustrative examples,
  not a live, constantly-updated threat-intelligence feed. A verdict of SAFE means
  "nothing in what RAT3 can check looked wrong" — not an absolute guarantee.
