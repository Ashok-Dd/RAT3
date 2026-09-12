# Decision Engine — turning four layers into one verdict

## What it's for

Each of the four layers produces its own independent 0–100 risk score and its own list of
findings. Nobody looks at four separate numbers and decides for themselves what they add
up to — the Decision Engine does that arithmetic once, consistently, every time.

## How the four scores are combined

Each layer's score is weighted by how trustworthy that *kind* of evidence generally is:

| Layer | Weight | Why this weight |
|---|---|---|
| Layer 1 — App Safety | 20% | Solid signal, but manifest-only — easy for an app to look fine on paper. |
| Layer 2 — Permission↔Function Match | 20% | Useful corroborating evidence, but individually low-confidence (see that layer's docs). |
| Layer 3 — Signature & Reputation | 35% | The only layer capable of *confirmed* evidence (a real hash/signature match), so it carries the most weight. |
| Layer 4 — ML Classifier | 25% | Strong, data-driven signal, but a model's output is still a probability, not a certainty. |

The weighted combination gives one number from 0–100.

## When a layer can't finish its job

If a layer fails to complete its analysis (for example, the manifest was too malformed to
parse fully), that layer's contribution to the final score is **capped low** — a failed
layer can produce a weak signal at most, and specifically **can never by itself push a
verdict into MALICIOUS territory**. The final result also plainly says which layer
couldn't complete, so a MALICIOUS or SUSPICIOUS verdict reached partly on incomplete data
is never presented as a clean, fully-informed answer.

## Escalation: when a single layer overrides the math

Two specific situations bypass the normal weighted average and force the score up to at
least the edge of MALICIOUS territory, regardless of what the other layers found:

1. **Layer 3 reports a hard hit** — the file's hash matched the known-malware blocklist,
   a named malware-family signature matched, or a trusted app's signing certificate
   didn't match (repackaging).
2. **Layer 4's ML ensemble unanimously agrees** — all four models independently
   classified the app as malware.

The reasoning: these are the two situations where RAT3 has something closer to *proof*
rather than a probabilistic hunch, so they're allowed to override a lower weighted-average
score that other, weaker signals alone produced.

## The three final bands

| Final score | Verdict |
|---|---|
| 0–29 | **SAFE** |
| 30–59 | **SUSPICIOUS** |
| 60–100 | **MALICIOUS** |

## Worked examples

**A legitimate but heavily-permissioned fitness app.** Layer 1 scores moderately (many
permissions, but no accessibility abuse). Layer 2 finds no dangerous APIs. Layer 3 finds
nothing (real certificate, no blocklist match, no obfuscation). Layer 4's ML ensemble
scores it low (8% average malware probability, 0/4 models voting malware).
→ Weighted score lands comfortably in SAFE — no escalation triggers, because nothing was
confirmed and the ML ensemble wasn't unanimous on malware.

**A repackaged clone of a popular app.** Layer 1 scores moderately. Layer 2 finds a
`DexClassLoader` reference. Layer 3 finds a signing-certificate mismatch against the real
app's known certificate — **a hard hit**. Layer 4's ML ensemble scores it at 55% (2 of 4
models voting malware — not unanimous).
→ Even if the plain weighted average would have landed in SUSPICIOUS territory, the
Layer 3 hard hit forces the final score up to the escalation floor, and the verdict is
**MALICIOUS** — with the summary explicitly stating a signing-certificate mismatch was
found.

**An app whose manifest partially failed to parse** (a corrupted or deliberately malformed
file), but what little Layer 1 could read looked heavy-handed, and Layer 3 and 4 found
nothing.
→ Layer 1's contribution is capped at a low ceiling because it's marked as an
analysis error, so this single degraded layer cannot push the verdict to MALICIOUS on its
own; the final result explicitly notes that Layer 1 could not complete analysis, so the
verdict reflects partial data.

## What the summary text tells you

Alongside the SAFE/SUSPICIOUS/MALICIOUS label and the numeric score, the result screen
always includes a plain-language summary that names the *specific* reason for an
escalated verdict — "a known malware signature or reputation hit was found," or "the ML
ensemble classified it as malware (4/4 models agree)" — rather than presenting a bare
number with no explanation.
