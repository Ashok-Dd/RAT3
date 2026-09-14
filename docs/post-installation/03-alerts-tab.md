# Alerts Tab

## What it's for

Every finding from every layer of the post-installation monitor lands here — this is the
"show me everything, and let me filter it" view, versus the Dashboard's "give me the
summary" view.

## What's on screen

- A filter bar: **All / Low / Medium / High / Critical**, so you can jump straight to
  what matters most.
- Each alert shows its severity badge, its title, which layer/source raised it (Runtime
  Monitor, Network Monitor, Permission Tracker, Connection Monitor, App Scanner, Risk
  Engine), and how long ago it fired.
- Tapping an alert expands it to the full explanation — every alert in RAT3 is written to
  say specifically *why* it fired, never just "risk detected" with no reasoning attached.

## Where alerts come from

Every monitoring layer feeds into one shared Alert Engine — Runtime Monitor, Network
Monitor, Permission Tracker, the Connection Monitor, the Scan All Apps audit, and the Risk
Engine's own device-state checks all push their findings through the same pipeline, which
is what lets this one tab show everything in one place with consistent behavior.

## Why you don't see the same alert repeated forever

A raw, naive implementation would re-show "USB debugging is enabled" every single scan
cycle for as long as the condition holds — which would very quickly become noise you
learn to ignore, defeating the point of an alert. RAT3's Alert Engine applies **three
layers of deduplication**:

1. **Never repeat the exact same finding twice in one session.** Once "Device is rooted"
   has been shown, it won't show again until the app restarts, even though the underlying
   monitor keeps re-checking root status on every cycle.
2. **A cooldown window for similar findings even from a different source.** If two
   different layers happen to raise something with the same title within a short window
   (30 minutes for critical findings, down to 5 minutes for low-severity ones), the second
   one is suppressed rather than shown as a duplicate.
3. **A fresh start for each full app scan.** Findings from the "Scan All Apps" audit are
   specifically replaced by the next audit's results, so you're always looking at the
   latest audit's findings for that feature, not an ever-growing pile of old ones.

## Why a finding doesn't always trigger a phone notification

Every alert is always visible here in the Alerts tab, but not every alert pushes a
separate phone notification — specifically, device-level conditions like "rooted" or
"USB debugging enabled" are only pushed as a notification **once**, by whichever part of
the monitor is guaranteed to keep running even if the app itself gets closed. A second
part of the monitor that independently notices the same condition still records it here
for transparency, it just doesn't also buzz your phone a second time for the same thing.

## Worked example

A background scan cycle discovers: the device is rooted (first time this session), USB
debugging is enabled (also first time), and 15 minutes later a second scan cycle notices
the device is *still* rooted and USB debugging is *still* enabled.

- **First cycle:** both findings appear in the Alerts tab, and both trigger exactly one
  phone notification each.
- **Second cycle:** the underlying conditions are re-detected (as they should be — nothing
  changed), but neither shows up as a *new* entry in the Alerts tab, and neither
  re-triggers a notification. You are not spammed for a condition that hasn't changed.

If instead the device were un-rooted and then rooted again later, that would be a genuinely
new event and would surface again, since the dedup applies per stable finding, not as a
blanket "never mention this again."
