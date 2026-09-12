# Risk Scoring Engine

## What it's for

This is what actually computes the [Dashboard](01-dashboard.md)'s single overall
0–100 score and its five-tier status. Unlike [Layer 4 of the pre-installation
scanner](../pre-installation/04-ml-malware-classifier.md), this is **not** a machine-learning
model — it's a transparent, hand-weighted rule engine, chosen deliberately for this job
because the Dashboard's score needs to be explainable in plain English at every level:
*this* score came from *these* specific rules firing, not from a black box.

## Where the input comes from

Roughly once a minute (and right after every scan), a data-collection step reads close to
**65 individual signals** directly from the device — real numbers and yes/no facts, not
estimates — grouped into six categories:

| Category | What it covers | A few of its signals |
|---|---|---|
| **Sensor Behavior** | Camera/microphone/location activity patterns | Is the camera active right now; was it active between 11 PM–6 AM; how many apps have background-location access |
| **Permission Behavior** | How sensitive permissions are actually being used across the device | How many apps hold high-risk permissions; what fraction of granted permissions belong to apps that haven't been opened in a week |
| **App Behavior** | Installed-app patterns | How many sideloaded apps; how many installed in the last 7 days; how many use an accessibility service |
| **System Behavior** | Device security posture | Root status, USB debugging, developer options, CPU/memory pressure, battery drain rate |
| **Network & Resource** | Data movement patterns | Background data sent, data sent during idle hours, number of distinct remote IPs contacted, small-packet "beacon" pattern |
| **Aggregated Correlations** | Signals that only mean something when combined | How often sensor activity and network activity happen at the same time; how much more background activity there is than foreground activity |

## How the six categories combine into one score

Each category produces its own 0–100 sub-score from the rules that fired within it (see
below), and the six sub-scores are combined with fixed weights:

| Category | Weight | Why this weight |
|---|---|---|
| Sensor Behavior | 25% | Direct hardware-abuse signal — the strongest evidence of active spying. |
| Network & Resource | 25% | Direct data-exfiltration signal. |
| App Behavior | 20% | Captures sideloading and accessibility-abuse risk at the device level. |
| System Security | 15% | Device exposure (root, debugging) — real risk, but not evidence of an active RAT by itself. |
| Permission Behavior | 10% | Permission misuse patterns, generally slower-moving/less urgent than the above. |
| Aggregated Correlations | 5% | A bonus layer that rewards *combinations* the other categories already partially captured individually. |

This weighted total is what maps onto the Dashboard's five-tier status
(0–20 SAFE, 21–40 MONITOR, 41–60 SUSPICIOUS, 61–80 HIGH RISK, 81–100 CRITICAL).

## How individual rules work

Every rule reads one or more of the ~65 signals and, if it fires, both adds points to
its category's sub-score and produces a specific, plain-language reason — nothing scores
silently. A representative sample:

| Category | Rule | Severity of the reason shown |
|---|---|---|
| Sensor | Camera or microphone is in use right now | High |
| Sensor | Camera or microphone was active between 11 PM and 6 AM | Critical |
| Sensor | Camera or microphone was active while the screen was off | Critical |
| Sensor | Network data was sent while a sensor was active | Critical — "matches surveillance/RAT exfiltration patterns" |
| Network | A malicious connection was detected | Critical |
| Network | More than 50 MB sent in the background | High |
| Network | Many tiny, frequent packets (a beacon/heartbeat pattern) | High |
| App | 3 or more apps installed outside the Play Store | Critical |
| App | Any app is using an Accessibility Service | Critical |
| System | Device is rooted | Critical |
| System | USB debugging is enabled | High |
| Permission | Device Administrator rights are active on some app | Critical |
| Aggregated | Strong correlation between sensor activity and network uploads | Critical — "a primary indicator of a surveillance RAT" |

Rules within a category are additive and capped at 100 for that category, so several
moderate findings in one category can add up to a high sub-score even though no single
one of them would.

## Worked example

**A device where:** the camera briefly activated at 1 AM (Sensor: idle-hours activity,
critical), a burst of background data went out at the same time (Network: idle-hours
data, high; plus the Aggregated correlation rule, since sensor and network activity lined
up), and two sideloaded apps are installed (App: a smaller contribution, since it's below
the "3 or more" threshold for the higher tier).

- **Sensor sub-score:** driven up mainly by the idle-hours camera activity rule.
- **Network sub-score:** driven up by the idle-hours data rule.
- **Aggregated sub-score:** driven up by the sensor-network correlation rule — this is the
  category specifically designed to reward exactly this kind of combination.
- **App sub-score:** a modest contribution from the two sideloaded apps, not enough alone
  to be alarming.
- **System and Permission sub-scores:** low, nothing unusual there.

Weighted together, this combination — camera activity at an unusual hour *plus* a data
upload at the same moment — is exactly the pattern the Aggregated category exists to
catch, and pushes the overall score well past the SUSPICIOUS line even though no single
category alone would have crossed it. This mirrors the Dashboard doc's own worked example,
from the scoring-engine side of the same event.

## Honesty notes

- **This is rule-based, not machine-learning.** Every weight and threshold here was
  chosen by hand based on how each signal relates to real RAT/spyware behavior, and can be
  explained line by line — deliberately, so the Dashboard's number is never a mystery.
- **A signal that Android won't let RAT3 see reads as "0," not as "clean."** If usage
  access wasn't granted, background-activity-dependent signals simply can't populate, and
  the relevant part of the score reflects that missing visibility rather than presenting a
  false all-clear.
