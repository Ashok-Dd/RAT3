import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/layers/feature_engine/device_features.dart';

/// RuleBasedScorer
///
/// Evaluates all 60+ DeviceFeatures using a weighted rule engine
/// and produces a final composite risk score (0–100).
///
/// Architecture:
///   6 category sub-scores  (each 0–100)
///   Weighted composite      → final score 0–100
///   Triggered rules         → human-readable reasons
///
/// Category weights (must sum to 1.0):
///   Sensor Behavior    25%  ← highest: direct hardware abuse signal
///   Network/Resource   25%  ← direct: data exfiltration signal
///   App Behavior       20%  ← sideloaded/malicious app risk
///   System Security    15%  ← device exposure (root, USB debug)
///   Permission Abuse   10%  ← permission misuse
///   Aggregated         5%   ← correlation and entropy bonuses
class RuleBasedScorer {
  static const double _wSensor = 0.25;
  static const double _wNetwork = 0.25;
  static const double _wApp = 0.20;
  static const double _wSystem = 0.15;
  static const double _wPermission = 0.10;
  static const double _wAggregated = 0.05;

  /// Score the features and return a ScoredResult.
  ScoredResult score(DeviceFeatures f) {
    final reasons = <RuleHit>[];

    final sensor = _scoreSensor(f, reasons);
    final network = _scoreNetwork(f, reasons);
    final app = _scoreApp(f, reasons);
    final system = _scoreSystem(f, reasons);
    final perm = _scorePermission(f, reasons);
    final agg = _scoreAggregated(f, reasons);

    final composite =
        (sensor * _wSensor +
                network * _wNetwork +
                app * _wApp +
                system * _wSystem +
                perm * _wPermission +
                agg * _wAggregated)
            .clamp(0.0, 100.0);

    // Sort reasons by severity (critical first)
    reasons.sort((a, b) => b.severity.index.compareTo(a.severity.index));

    return ScoredResult(
      composite: composite.round(),
      sensorScore: sensor.round(),
      networkScore: network.round(),
      appScore: app.round(),
      systemScore: system.round(),
      permissionScore: perm.round(),
      aggregatedScore: agg.round(),
      triggeredRules: reasons,
    );
  }

  // ═══════════════════════════════════════════════════════════════
  // 1. SENSOR BEHAVIOR  (0–100)
  // ═══════════════════════════════════════════════════════════════
  double _scoreSensor(DeviceFeatures f, List<RuleHit> r) {
    double s = 0;

    // Camera active right now ← strongest signal
    if (f.cameraActiveNow) {
      s += 30;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Camera is in use right now',
          'An app has the camera open at this moment.',
        ),
      );
    }

    // Mic active right now
    if (f.micActiveNow) {
      s += 30;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Microphone is in use right now',
          'An app has the microphone open at this moment.',
        ),
      );
    }

    // Sensor active during idle hours (23:00–06:00)
    if (f.cameraActiveDuringIdle) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Camera active during idle hours',
          'Camera was open between 23:00–06:00 — highly abnormal.',
        ),
      );
    }
    if (f.micActiveDuringIdle) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Microphone active during idle hours',
          'Microphone was open between 23:00–06:00 — highly abnormal.',
        ),
      );
    }

    // Sensor active when screen off
    if (f.cameraActiveWhenScreenOff) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Camera active with screen off',
          'Camera is open while the device screen is off — very suspicious.',
        ),
      );
    }
    if (f.micActiveWhenScreenOff) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Microphone active with screen off',
          'Microphone is recording while the screen is off.',
        ),
      );
    }

    // Mic active outside calls
    if (f.micActiveOutsideCalls && !f.micActiveDuringIdle) {
      s += 10;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Microphone active outside of calls',
          'Mic is in use but no phone call is active.',
        ),
      );
    }

    // Background location abuse
    if (f.locationBgAppsCount >= 3) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.locationBgAppsCount} apps have background location',
          'Multiple apps can track your location even when not in use.',
        ),
      );
    } else if (f.locationBgAppsCount > 0) {
      s += 7;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.locationBgAppsCount} app has background location access',
          'An app can track your location in the background.',
        ),
      );
    }

    // Deliberately not scored: this device has no way to detect an actual location
    // *read* (there's no live "location active now" API the way camera/mic have one) --
    // locationActiveDuringIdle was really just "an app holds background-location
    // permission" AND "it's currently 23:00-06:00", with no access event verified at
    // all, yet was worded to assert one ("Location was accessed between 23:00-06:00")
    // for any phone with a weather/maps/delivery app installed, every single night.
    // The permission fact itself is already scored, honestly, by locationBgAppsCount
    // just above.

    // High irregularity score
    if (f.sensorUsageIrregularity > 60) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Irregular sensor usage pattern',
          'Sensor activity is inconsistent with normal usage patterns.',
        ),
      );
    }

    // Sensor + network correlation
    if (f.networkDuringSensorUsage) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Network active during sensor usage',
          'Data is being sent while camera or mic is active — '
              'this matches surveillance/RAT exfiltration patterns.',
        ),
      );
    }

    return s.clamp(0, 100);
  }

  // ═══════════════════════════════════════════════════════════════
  // 2. NETWORK & RESOURCE  (0–100)
  // ═══════════════════════════════════════════════════════════════
  double _scoreNetwork(DeviceFeatures f, List<RuleHit> r) {
    double s = 0;

    // Malicious connections
    if (f.maliciousConnectionCount > 0) {
      s += (f.maliciousConnectionCount * 40).clamp(0, 80).toDouble();
      r.add(
        RuleHit(
          AlertSeverity.critical,
          '${f.maliciousConnectionCount} malicious network connection(s)',
          'Active data exfiltration or C2 communication detected.',
        ),
      );
    }

    // Suspicious connections
    if (f.suspiciousConnectionCount > 0) {
      s += (f.suspiciousConnectionCount * 10).clamp(0, 30).toDouble();
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.suspiciousConnectionCount} suspicious connection(s)',
          'Unusual network traffic detected.',
        ),
      );
    }

    // Large background data
    if (f.bgDataSentMb > 50) {
      s += 30;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Large background upload: ${f.bgDataSentMb.toStringAsFixed(1)} MB',
          'Apps have sent over 50 MB in the background.',
        ),
      );
    } else if (f.bgDataSentMb > 10) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Elevated background upload: ${f.bgDataSentMb.toStringAsFixed(1)} MB',
          'Apps have sent over 10 MB in the background.',
        ),
      );
    }

    // Data sent during idle hours
    if (f.dataSentDuringIdleMb > 5) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Data sent during idle hours: ${f.dataSentDuringIdleMb.toStringAsFixed(1)} MB',
          'Significant data transfer occurred between 23:00–06:00.',
        ),
      );
    }

    // Data sent without user interaction
    if (f.dataSentWithoutInteraction > 5) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Data sent without user interaction',
          'Network uploads detected with no active app in foreground.',
        ),
      );
    }

    // Many unique IPs (C2 rotation pattern)
    if (f.uniqueRemoteIpsCount > 20) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.uniqueRemoteIpsCount} unique remote IPs contacted',
          'High number of external IPs suggests C2 communication.',
        ),
      );
    } else if (f.uniqueRemoteIpsCount > 10) {
      s += 10;
    }

    // Frequent small packets (C2 beacon pattern)
    if (f.frequentSmallPackets) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Frequent small packet transmissions',
          'Many tiny network packets detected — matches RAT beacon/heartbeat pattern.',
        ),
      );
    }

    // CPU spikes when screen off
    if (f.cpuSpikesWhenScreenOff > 3) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.cpuSpikesWhenScreenOff.toInt()} CPU spikes while screen is off',
          'Background processes are consuming CPU without user activity.',
        ),
      );
    }

    // Mic + network correlation (already counted in sensor but add network weight too)
    if (f.dataSentWhenMicActive) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Data upload while microphone is active',
          'Network upload and active microphone at the same time.',
        ),
      );
    }
    if (f.dataSentWhenCameraActive) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Data upload while camera is active',
          'Network upload and active camera at the same time.',
        ),
      );
    }

    // Battery drain (fast drain = intensive background activity)
    if (f.batteryDrainRatePerHour > 20) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Fast battery drain: ${f.batteryDrainRatePerHour.toStringAsFixed(1)}%/hr',
          'Battery draining rapidly — may indicate intensive background processes.',
        ),
      );
    }

    // High memory variance (repeatedly spikes and drops = suspicious service)
    if (f.memoryUsageVariance > 200) {
      s += 10;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'High memory usage variance',
          'Memory usage is erratic — a background service may be cycling.',
        ),
      );
    }

    return s.clamp(0, 100);
  }

  // ═══════════════════════════════════════════════════════════════
  // 3. APP BEHAVIOR  (0–100)
  // ═══════════════════════════════════════════════════════════════
  double _scoreApp(DeviceFeatures f, List<RuleHit> r) {
    double s = 0;

    // Apps the App Trust Engine's own evidence ladder already flagged NEEDS_REVIEW or
    // worse. Deliberately NOT a raw sideloaded/unknown-installer count: being installed
    // outside Play Store is not evidence of a RAT by itself — a developer's own dozen
    // sideloaded test builds, or a device that shipped with a dozen OEM-bundled apps
    // (excluded from scanning entirely, see isOemPreinstalled), are not "risk" just for
    // existing. Only apps that already show some other concerning signal count here.
    if (f.flaggedAppCount >= 3) {
      s += 40;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          '${f.flaggedAppCount} apps flagged by the App Trust Engine',
          'Multiple apps show real evidence beyond just their install source — see Scan All Apps.',
        ),
      );
    } else if (f.flaggedAppCount > 0) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.flaggedAppCount} app(s) flagged by the App Trust Engine',
          'At least one app shows real evidence beyond just its install source — see Scan All Apps.',
        ),
      );
    }

    // Recent installs
    if (f.recentlyInstalledAppCount >= 3) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.recentlyInstalledAppCount} apps installed in last 7 days',
          'Burst of recent app installs — review each carefully.',
        ),
      );
    } else if (f.recentlyInstalledAppCount > 0) {
      s += 8;
    }

    // Frequent install/uninstall pattern (hiding traces)
    if (f.frequentInstallUninstallPattern) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Frequent install/uninstall pattern',
          'Rapid installing and uninstalling of apps may indicate malware hiding activity.',
        ),
      );
    }

    // Old SDK targets (pre-Oreo = before permission restrictions)
    if (f.appsTargetingOldSdkCount >= 3) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.appsTargetingOldSdkCount} apps targeting old Android SDK',
          'Older target SDK bypasses modern permission and security controls.',
        ),
      );
    } else if (f.appsTargetingOldSdkCount > 0) {
      s += 5;
    }

    // Accessibility abuse: NOT scored from the raw "is any accessibility service active
    // anywhere on the device" boolean (informational only — see appsWithAccessibilityCount
    // in the summary string). That boolean can't tell a legitimate screen reader or a
    // password manager's autofill apart from actual abuse -- it's the exact declared/
    // active-without-correlation shape already fixed elsewhere in this file. An
    // accessibility service on an app that ISN'T already Play-Store-trusted is real
    // evidence and is already captured by flaggedAppCount above, via the App Trust
    // Engine's own evidence ladder (which escalates accessibility+overlay/admin combos to
    // its top tier) -- scoring it a second time here would be the same fact counted twice.

    // Many background processes
    if (f.appsRunningInBgCount > 15) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.appsRunningInBgCount} processes running in background',
          'Abnormally high number of background processes.',
        ),
      );
    } else if (f.appsRunningInBgCount > 8) {
      s += 8;
    }

    // Background activity during idle
    if (f.appsRunningDuringIdleCount > 3) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.appsRunningDuringIdleCount} apps active during idle hours',
          'Multiple apps had activity between 23:00–06:00.',
        ),
      );
    }

    return s.clamp(0, 100);
  }

  // ═══════════════════════════════════════════════════════════════
  // 4. SYSTEM SECURITY  (0–100)
  // ═══════════════════════════════════════════════════════════════
  double _scoreSystem(DeviceFeatures f, List<RuleHit> r) {
    double s = 0;

    // Root — most severe system signal
    if (f.rootDetected) {
      s += 60;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Device is rooted',
          'Root access detected. Rooted devices have severely reduced security '
              'and are extremely vulnerable to RAT installation.',
        ),
      );
    }

    // USB debugging / developer options: deliberately NOT scored on their own. These are
    // completely normal, common settings for developers and power users — a RAT's threat
    // model is remote/network control, not "a computer is physically plugged into your
    // unlocked phone." Scoring them as risk by default punished exactly the audience most
    // likely to have them on for entirely legitimate reasons. Root + USB debugging together
    // is the one combination worth naming: it meaningfully widens what anyone with local
    // physical access to the device could do, which root or ADB access alone don't imply.
    if (f.rootDetected && f.usbDebuggingEnabled) {
      s += 10;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Rooted device with USB debugging enabled',
          'Together these meaningfully widen what anyone with physical access to this '
              'device could do — on their own, neither is unusual for a developer.',
        ),
      );
    }

    // Unknown sources: also common for legitimate reasons (F-Droid, corporate MDM,
    // developers) — only worth flagging when there's also actual evidence an app
    // installed that way is showing concerning behavior, not just the setting existing.
    if (f.unknownSourcesEnabled && f.flaggedAppCount > 0) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Install from unknown sources is enabled, with flagged apps present',
          'Sideloading is allowed, and at least one sideloaded app shows real '
              'evidence beyond its install source — see Scan All Apps.',
        ),
      );
    }

    // Play Protect verification off, alone, is a weak signal — same philosophy as unknown
    // sources: a setting is a fact about the device, not evidence of a specific threat,
    // until correlated with something else. It also disables Android's own background
    // malware scanning of every installed app, so it's still worth a small, low-severity
    // mention rather than being silently collected and never shown (this was previously
    // read and dropped entirely — see the App Trust Engine doc's honesty note).
    if (f.verifyAppsDisabled) {
      s += 8;
      r.add(
        RuleHit(
          AlertSeverity.low,
          'Play Protect app verification is turned off',
          'Android\'s own background malware scanning for newly installed apps is '
              'disabled. Not evidence of compromise by itself, but it removes a layer '
              'of protection this device would otherwise have.',
        ),
      );
    }

    // Active device admin apps
    if (f.activeDeviceAdminCount > 1) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          '${f.activeDeviceAdminCount} apps have device admin rights',
          'Multiple device admin apps — check if any is unexpected.',
        ),
      );
    } else if (f.activeDeviceAdminCount == 1 && !f.deviceAdminActive) {
      s += 10;
    }

    // Accessibility service usage isn't scored here or in App Behavior as a raw
    // device-wide boolean — see App Behavior's flaggedAppCount comment for why.

    // High CPU usage
    if (f.cpuUsagePercent > 85) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'CPU at ${f.cpuUsagePercent.toStringAsFixed(0)}%',
          'Device CPU is critically high — a background process may be active.',
        ),
      );
    } else if (f.cpuUsagePercent > 60) {
      s += 8;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Elevated CPU: ${f.cpuUsagePercent.toStringAsFixed(0)}%',
          'CPU usage is elevated above normal.',
        ),
      );
    }

    // High memory usage
    if (f.memoryUsagePercent > 90) {
      s += 10;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Critical memory usage: ${f.memoryUsagePercent.toStringAsFixed(0)}%',
          'Device RAM is critically low.',
        ),
      );
    }

    // Battery optimization disabled for many apps
    if (f.batteryOptDisabledAppsCount > 5) {
      s += 10;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.batteryOptDisabledAppsCount} apps have battery optimization disabled',
          'These apps can run freely in background without restriction.',
        ),
      );
    }

    return s.clamp(0, 100);
  }

  // ═══════════════════════════════════════════════════════════════
  // 5. PERMISSION ABUSE  (0–100)
  // ═══════════════════════════════════════════════════════════════
  double _scorePermission(DeviceFeatures f, List<RuleHit> r) {
    double s = 0;

    // High-risk permission count
    if (f.highRiskPermissionCount > 10) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.highRiskPermissionCount} high-risk permissions granted',
          'Many sensitive permissions (camera, mic, location, SMS) are granted.',
        ),
      );
    } else if (f.highRiskPermissionCount > 5) {
      s += 12;
    }

    // Total dangerous permissions
    if (f.dangerousPermissionCount > 20) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${f.dangerousPermissionCount} DANGEROUS permissions granted',
          'Large number of Android DANGEROUS-level permissions in use.',
        ),
      );
    } else if (f.dangerousPermissionCount > 10) {
      s += 10;
    }

    // Unused but granted ratio
    if (f.unusedButGrantedRatio > 0.5) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          '${(f.unusedButGrantedRatio * 100).toStringAsFixed(0)}% of permissions unused',
          'Over half of granted permissions belong to apps that are never used.',
        ),
      );
    } else if (f.unusedButGrantedRatio > 0.25) {
      s += 10;
    }

    // Permission vs usage mismatch
    if (f.permissionsVsUsageMismatch > 50) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'High permission-vs-usage mismatch',
          'Multiple apps hold sensitive permissions but have near-zero usage time.',
        ),
      );
    }

    // Background location
    if (f.bgLocationPermissionGranted && f.locationBgAppsCount >= 2) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.locationBgAppsCount} apps have background location',
          'Background location allows tracking even when apps are closed.',
        ),
      );
    }

    // Device admin
    if (f.deviceAdminActive) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Device Administrator permission is active',
          'An app has device admin rights — can wipe device and block uninstall.',
        ),
      );
    }

    // Accessibility service usage isn't scored here or in App Behavior as a raw
    // device-wide boolean — see App Behavior's flaggedAppCount comment for why.

    return s.clamp(0, 100);
  }

  // ═══════════════════════════════════════════════════════════════
  // 6. AGGREGATED CORRELATIONS  (0–100)
  // ═══════════════════════════════════════════════════════════════
  double _scoreAggregated(DeviceFeatures f, List<RuleHit> r) {
    double s = 0;

    // Sensor-to-network correlation (strongest RAT indicator)
    if (f.sensorToNetworkCorrelation > 0.6) {
      s += 50;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Strong sensor–network correlation detected',
          'Sensor activity (mic/camera) consistently coincides with network '
              'uploads — this is a primary indicator of a surveillance RAT.',
        ),
      );
    } else if (f.sensorToNetworkCorrelation > 0.3) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Moderate sensor–network correlation',
          'Sensor activity correlates with network uploads.',
        ),
      );
    }

    // Overall idle anomaly
    if (f.overallIdleAnomalyScore > 60) {
      s += 30;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'High activity during idle hours',
          'Significant device activity detected between 23:00–06:00.',
        ),
      );
    } else if (f.overallIdleAnomalyScore > 30) {
      s += 15;
    }

    // Low FG/BG ratio (more background than foreground = suspicious)
    if (f.fgToBgActivityRatio < 0.3) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'Low foreground-to-background activity ratio',
          'Much more background activity than foreground — abnormal usage pattern.',
        ),
      );
    }

    // High sensor entropy
    if (f.sensorActivityEntropy > 0.8) {
      s += 10;
      r.add(
        RuleHit(
          AlertSeverity.medium,
          'High sensor activity entropy',
          'Sensors are firing in an unpredictable, non-user-driven pattern.',
        ),
      );
    }

    return s.clamp(0, 100);
  }
}

// ── Result Models ─────────────────────────────────────────────────────────

/// The full output of the rule engine.
class ScoredResult {
  final int composite; // 0–100 final score
  final int sensorScore;
  final int networkScore;
  final int appScore;
  final int systemScore;
  final int permissionScore;
  final int aggregatedScore;
  final List<RuleHit> triggeredRules;

  const ScoredResult({
    required this.composite,
    required this.sensorScore,
    required this.networkScore,
    required this.appScore,
    required this.systemScore,
    required this.permissionScore,
    required this.aggregatedScore,
    required this.triggeredRules,
  });

  /// Critical and high rules only.
  List<RuleHit> get highPriorityRules => triggeredRules
      .where((r) => r.severity.index >= AlertSeverity.high.index)
      .toList();

  String get breakdown =>
      'composite=$composite '
      'sensor=$sensorScore net=$networkScore app=$appScore '
      'sys=$systemScore perm=$permissionScore agg=$aggregatedScore';
}

class RuleHit {
  final AlertSeverity severity;
  final String title;
  final String description;
  const RuleHit(this.severity, this.title, this.description);
}
