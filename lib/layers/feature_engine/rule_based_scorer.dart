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

    // Location active during idle
    if (f.locationActiveDuringIdle) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Location accessed during idle hours',
          'Location was accessed between 23:00–06:00.',
        ),
      );
    }

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

    // Sideloaded apps (biggest single risk signal)
    if (f.nonPlayStoreAppCount >= 3) {
      s += 40;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          '${f.nonPlayStoreAppCount} sideloaded / non-Play Store apps',
          'Multiple apps installed outside Play Store — high RAT risk.',
        ),
      );
    } else if (f.nonPlayStoreAppCount > 0) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.nonPlayStoreAppCount} sideloaded app(s)',
          'Apps installed outside Google Play Store detected.',
        ),
      );
    }

    // Unknown installer
    if (f.unknownInstallerAppCount > 0) {
      s += 15;
      r.add(
        RuleHit(
          AlertSeverity.high,
          '${f.unknownInstallerAppCount} app(s) with unknown installer',
          'Apps whose install source cannot be verified.',
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

    // Accessibility abuse
    if (f.appsWithAccessibilityCount > 0) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          '${f.appsWithAccessibilityCount} app(s) using Accessibility Service',
          'Accessibility services can read screen content and simulate touches — '
              'extremely high risk if granted to unknown apps.',
        ),
      );
    }

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

    // USB debugging
    if (f.usbDebuggingEnabled) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'USB debugging (ADB) is enabled',
          'A connected computer can fully access your device via ADB.',
        ),
      );
    }

    // Developer options
    if (f.developerOptionsEnabled && !f.usbDebuggingEnabled) {
      s += 10;
      r.add(
        RuleHit(
          AlertSeverity.low,
          'Developer options are enabled',
          'Developer mode exposes additional device access features.',
        ),
      );
    }

    // Unknown sources
    if (f.unknownSourcesEnabled) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Install from unknown sources is enabled',
          'Apps can be installed from any source, bypassing Play Store security.',
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

    // Accessibility services
    if (f.accessibilityServicesActive) {
      s += 20;
      r.add(
        RuleHit(
          AlertSeverity.high,
          'Accessibility services active',
          'One or more apps have accessibility service access enabled.',
        ),
      );
    }

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

    // Accessibility permission
    if (f.accessibilityPermissionActive) {
      s += 25;
      r.add(
        RuleHit(
          AlertSeverity.critical,
          'Accessibility permission is active',
          'An app can read screen content, inputs, and simulate user actions.',
        ),
      );
    }

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
