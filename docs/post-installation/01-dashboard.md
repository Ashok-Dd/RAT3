# Dashboard Tab

## What it's for

The one screen you'd check to answer, at a glance: **"is my device currently okay?"**
Everything else in the app is detail; the Dashboard is the summary.

## What's on screen

### The risk ball and Device Security Status

A single 0–100 number, colored and labeled with one of five statuses:

| Score | Status | What it means |
|---|---|---|
| 0–20 | **SAFE** | No strong indicators of RAT malware were found within what RAT3 can inspect. |
| 21–40 | **MONITOR** | A few minor signals are being watched — nothing conclusive yet. |
| 41–60 | **SUSPICIOUS** | Some indicators are worth reviewing. |
| 61–80 | **HIGH RISK** | Multiple correlated indicators were found — review soon. |
| 81–100 | **CRITICAL** | Strong, correlated indicators of compromise — review now. |

This is deliberately **five** bands, not a simple three-way safe/warning/danger split —
so that a device with one mildly unusual signal reads very differently from a device with
several serious, correlated ones stacked together, instead of both landing in the same
vague "warning" bucket.

Directly under the score, a plain-language line always spells out what that status
actually means (using the exact wording in the table above) — the goal is that you never
have to guess what a bare number implies.

### Findings by severity

A row of counts — Critical / High / Medium / Info — giving an at-a-glance breakdown of
*how many* things were found at each severity, without needing to open the Alerts tab.

### Monitoring / Alerts / Links summary cards

- **Monitoring** — ON or OFF, i.e. is the background watcher currently active.
- **Alerts** — how many findings are currently critical or high severity.
- **Links** — how many network connections/entries the Network layer currently has on
  record (see the [Network tab](02-network-tab.md)).

### Risk Breakdown

The overall score isn't one opaque number — it's built from six weighted categories, shown
here as individual bars so you can see *which kind* of behavior is driving the score:

| Category | Weight in the overall score |
|---|---|
| Sensor Behavior (camera/mic/location abuse) | 25% |
| Network & Resource (data exfiltration signals) | 25% |
| App Behavior (sideloading, accessibility abuse, install patterns) | 20% |
| System Security (root, USB debugging, developer options) | 15% |
| Permission Behavior (permission misuse patterns) | 10% |
| Aggregated Correlations (cross-signal patterns like sensor+network together) | 5% |

The full mechanics of how each category's number is calculated — and a worked example —
are in [Risk Scoring Engine](07-risk-scoring-engine.md).

### Recent Alerts

A short list of the latest findings, each with its severity badge and how long ago it
fired — a preview of the full [Alerts tab](03-alerts-tab.md).

## Where the number comes from

The Dashboard doesn't compute anything itself — it displays the output of the
[Risk Scoring Engine](07-risk-scoring-engine.md), which runs automatically roughly once a
minute (and immediately after every manual or automatic scan), reading close to 65
individual real-device signals every time.

## Example: how the same device reads at two different moments

**Ordinary day:** device isn't rooted, USB debugging is off, no unusual sensor activity,
no sideloaded apps with excess background time, network traffic is all daytime, no
malicious-port hits. Score lands around 5–10 → **SAFE**, and the summary line reads "No
strong indicators of RAT malware were found within the areas RAT3 can inspect."

**After sideloading a sketchy "system tool" app that got granted an accessibility
service**, and that app happens to send a burst of data at 2 AM while the microphone
briefly shows as active: several categories move at once — App Behavior (accessibility
abuse), Sensor Behavior (mic active during idle hours), Network (idle-hours data), and
Aggregated Correlations (sensor+network overlap) all contribute simultaneously. The score
can jump well past the SUSPICIOUS line into HIGH RISK or CRITICAL territory in one scan
cycle, because several of the weighted categories fired together — exactly the
"correlation, not a single signal" principle this whole app is built around.
