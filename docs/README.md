# RAT3 Documentation

RAT3 is an Android security app built around one question:

> **Does this device show evidence of RAT (Remote Access Trojan) or spyware compromise —
> before or after an app gets installed?**

It does this in two halves, documented separately in this folder:

| Folder | Covers | When it runs |
|---|---|---|
| [`pre-installation/`](pre-installation/README.md) | Scanning a single `.apk` file **before you install it** | You pick a file, or open it from a file manager |
| [`post-installation/`](post-installation/README.md) | Watching the **live device** continuously **after** apps are already installed | Runs in the background all the time, once turned on |

There's also one cross-cutting page that isn't about a single tab: **[RAT Malware Behavior
Coverage](rat-behavior-coverage.md)** — a full list of real-world RAT/spyware behaviors,
each one marked as covered, partially covered, not yet covered, or impossible to observe
without root, with the honest reason behind every gap.

These are genuinely separate engines with separate data, separate screens, and separate
verdict systems — a file can pass the pre-installation scan and still get flagged later by
the post-installation monitor if it starts behaving suspiciously after install (or vice
versa: a heavy-permission app can look alarming on paper before install, and turn out
completely normal once it's actually running).

## How to read these docs

Each page is written around **what you see on screen and what it means**, not the code
behind it. Every page tries to answer four questions:

1. **What is this tab/feature for?** — the real-world question it answers.
2. **What does it actually look at?** — which signals, permissions, or behaviors it reads.
3. **How does it turn that into a verdict?** — the rule of thumb it applies, in plain terms.
4. **What does a real example look like?** — a worked scenario with realistic numbers.

## A rule that applies to every page in here

RAT3 is deliberately built to avoid one specific mistake: **treating a permission, a
network connection, or a background process as guilt by itself.** Every scoring
system described in these docs works the same way — a single ordinary signal (an app
holding a permission, sending some data, running in the background) is never enough on
its own to call something suspicious. It takes a **correlated combination** of signals —
the kind of combination normal apps don't produce but RAT-style malware does — before RAT3
raises its voice. Where that isn't possible (Android simply won't let an app see something),
the docs say so plainly instead of pretending otherwise.
