/// Central constants for RAT3 application
class AppConstants {
  AppConstants._();

  // App Info
  static const String appName = 'RAT3';
  static const String appVersion = '1.0.0';

  // This app's own Android package — single source of truth so "never report
  // on ourselves" checks can't drift out of sync across files.
  static const String selfPackageName = 'com.example.rat3';

  // Risk Score Thresholds
  static const int safeThreshold = 30;
  static const int suspiciousThreshold = 60;
  static const int dangerThreshold = 80;

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
}

/// Risk level enum with display labels
enum RiskLevel {
  safe,
  suspicious,
  dangerous;

  String get label {
    switch (this) {
      case RiskLevel.safe:
        return 'SAFE';
      case RiskLevel.suspicious:
        return 'WARNING';
      case RiskLevel.dangerous:
        return 'DANGER';
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
