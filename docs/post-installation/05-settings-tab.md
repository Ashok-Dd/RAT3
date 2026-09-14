# Settings Tab

## What it's for

The handful of controls that affect the monitor as a whole, rather than living inside a
specific feature.

## What's on screen

### Monitoring

- **Enable Monitoring** — the same master switch as the one on the
  [Scanner tab](04-scanner-tab.md): turns all five background layers, and the persistent
  background service, on or off together.
- **Push Notifications** — controls whether findings also trigger a phone notification.
  Turning this off doesn't stop RAT3 from finding things — everything still appears in the
  [Alerts tab](03-alerts-tab.md) and feeds the [Dashboard](01-dashboard.md)'s score exactly
  the same either way; this only controls whether it also interrupts you outside the app.

### Permissions

- **Fix permissions** — re-runs the same setup flow shown on first launch (notifications,
  usage access, battery-optimization exemption, camera/mic/location), for whenever you
  want to grant something you skipped earlier, or Android has revoked a permission on its
  own.

### Risk Score

- **Reset Risk Score** — clears all accumulated alerts and resets the Dashboard's score
  back to a clean starting state. Useful after you've resolved something (uninstalled a
  flagged app, disabled a suspicious accessibility service) and want the Dashboard to
  reflect the device's current state rather than history.

### About

Real, live values read directly from the installed app — not hardcoded placeholder text:

| Field | Shows |
|---|---|
| App | RAT3 |
| Version | The actual installed version number and build number |
| Platform | Flutter / Android |
| Build | Whether this is a debug or a release build |

## Why "reset" and "disable" are kept separate from each other

Turning monitoring off (in Settings or the Scanner tab) stops new checks from running, but
deliberately does **not** erase what's already been found — closing your eyes to new
information isn't the same thing as saying old findings no longer matter. Clearing that
history is a distinct, explicit action (**Reset Risk Score**), so the two can't be confused
with each other.
