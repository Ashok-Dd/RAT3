/// Central constants for RAT3 application
class AppConstants {
  AppConstants._();

  // App Info
  static const String appName = 'RAT3';
  static const String appVersion = '1.0.0';

  // This app's own Android package — single source of truth so "never report
  // on ourselves" checks can't drift out of sync across files.
  static const String selfPackageName = 'com.example.rat3';

  // Device Security Status thresholds (0-100 composite from RuleBasedScorer).
  // Five tiers instead of three: a single suspicious-looking signal shouldn't
  // read the same as multiple correlated strong ones.
  static const int monitorThreshold = 20;
  static const int suspiciousThreshold = 40;
  static const int highRiskThreshold = 60;
  static const int criticalThreshold = 80;

  // Scan Intervals (in minutes)
  static const List<int> scanIntervals = [5, 10, 15, 30, 60, 120, 180];
  static const int defaultScanInterval = 10;

  // CPU Spike Threshold (percentage)
  static const double cpuSpikeThreshold = 80.0;

  // Data Upload Threshold (bytes per minute)
  static const int dataUploadThreshold = 5 * 1024 * 1024; // 5MB/min

  // Max service restart count before alert
  static const int maxServiceRestarts = 5;

  // Notification Channel
  static const String notificationChannelId = 'rat_prevention_channel';
  static const String notificationChannelName = 'RAT Prevention Alerts';

  // SharedPreferences Keys
  static const String keyScanInterval = 'scan_interval_minutes';
  static const String keyLastScanTime = 'last_scan_time';
  static const String keyRiskScore = 'risk_score';
  static const String keyMonitoringEnabled = 'monitoring_enabled';
  static const String keyNotificationsEnabled = 'notifications_enabled';

  // Background Task ID
  static const String backgroundTaskId = 'rat_prevention_bg_scan';

  // Network indicator lists — illustrative, not a live threat-intel feed
  // (same honesty caveat as assets/blocklist.json). Shared by NetworkMonitor
  // (legacy byte-usage view) and ConnectionMonitor (real per-connection view)
  // so the two don't quietly drift out of sync.
  static const List<String> knownMaliciousIpPrefixes = [
    '185.220.',
    '185.100.',
    '194.165.',
    '5.188.',
    '45.142.',
    '193.32.',
  ];

  static const List<int> suspiciousPorts = [
    1337,
    4444,
    4445,
    6666,
    6667,
    8888,
    9999,
    31337,
  ];
}

/// Device Security Status — "does this device currently show evidence of RAT
/// compromise?" Deliberately separate from [AppTrustLevel] (app_models.dart),
/// which answers "should I be concerned about THIS app". Five tiers so a
/// single suspicious-looking signal doesn't read the same as several
/// correlated strong ones.
enum RiskLevel {
  safe,
  monitor,
  suspicious,
  highRisk,
  critical;

  String get label {
    switch (this) {
      case RiskLevel.safe:
        return 'SAFE';
      case RiskLevel.monitor:
        return 'MONITOR';
      case RiskLevel.suspicious:
        return 'SUSPICIOUS';
      case RiskLevel.highRisk:
        return 'HIGH RISK';
      case RiskLevel.critical:
        return 'CRITICAL';
    }
  }
}

/// Alert severity levels
enum AlertSeverity {
  low,
  medium,
  high,
  critical;

  String get label {
    switch (this) {
      case AlertSeverity.low:
        return 'LOW';
      case AlertSeverity.medium:
        return 'MEDIUM';
      case AlertSeverity.high:
        return 'HIGH';
      case AlertSeverity.critical:
        return 'CRITICAL';
    }
  }
}

/// Network traffic classification
enum TrafficCategory {
  safe,
  suspicious,
  malicious;

  String get label {
    switch (this) {
      case TrafficCategory.safe:
        return 'SAFE';
      case TrafficCategory.suspicious:
        return 'SUSPICIOUS';
      case TrafficCategory.malicious:
        return 'MALICIOUS';
    }
  }
}
