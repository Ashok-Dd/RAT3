import 'package:rat3/core/constants/app_constants.dart';

// ── Alert Model ────────────────────────────────────────────────────────────

class AlertEvent {
  final String id;
  final AlertSeverity severity;
  final String title;
  final String description;
  final String userFriendlyMessage;
  final DateTime timestamp;
  final String source; // Which layer generated this

  /// Whether AlertEngine should push an OS notification for this alert (it's
  /// still recorded and shown in-app either way). Defaults true; a layer sets
  /// this false when another layer is already the notifier of record for the
  /// same real-world condition — e.g. the native background scan already
  /// pushes for "device rooted" / "USB debugging enabled", so the Dart-side
  /// RuntimeMonitor detecting the same thing shouldn't push a second one.
  final bool notify;

  const AlertEvent({
    required this.id,
    required this.severity,
    required this.title,
    required this.description,
    required this.userFriendlyMessage,
    required this.timestamp,
    required this.source,
    this.notify = true,
  });

  AlertEvent copyWith({AlertSeverity? severity}) {
    return AlertEvent(
      id: id,
      severity: severity ?? this.severity,
      title: title,
      description: description,
      userFriendlyMessage: userFriendlyMessage,
      timestamp: timestamp,
      source: source,
      notify: notify,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'severity': severity.name,
    'title': title,
    'description': description,
    'userFriendlyMessage': userFriendlyMessage,
    'timestamp': timestamp.toIso8601String(),
    'source': source,
    'notify': notify,
  };

  factory AlertEvent.fromJson(Map<String, dynamic> json) => AlertEvent(
    id: json['id'] as String,
    severity: AlertSeverity.values.byName(json['severity'] as String),
    title: json['title'] as String,
    description: json['description'] as String,
    userFriendlyMessage: json['userFriendlyMessage'] as String,
    timestamp: DateTime.parse(json['timestamp'] as String),
    source: json['source'] as String,
    // Missing key (alerts persisted before this field existed) -> true, so
    // old data keeps its previous (notifying) behaviour.
    notify: json['notify'] as bool? ?? true,
  );
}

// ── Network Connection Model ───────────────────────────────────────────────

class NetworkConnection {
  final String id;
  final String domain;
  final String ipAddress;
  final int port;
  final TrafficCategory category;
  final int bytesSent;
  final int bytesReceived;
  final DateTime detectedAt;
  final bool isBackground;

  const NetworkConnection({
    required this.id,
    required this.domain,
    required this.ipAddress,
    required this.port,
    required this.category,
    required this.bytesSent,
    required this.bytesReceived,
    required this.detectedAt,
    required this.isBackground,
  });

  int get totalBytes => bytesSent + bytesReceived;
}

// ── Runtime Event Model ────────────────────────────────────────────────────

class RuntimeEvent {
  final String id;
  final RuntimeEventType type;
  final double value;
  final String details;
  final DateTime timestamp;

  const RuntimeEvent({
    required this.id,
    required this.type,
    required this.value,
    required this.details,
    required this.timestamp,
  });
}

enum RuntimeEventType {
  cpuSpike,
  backgroundExecution,
  serviceRestart,
  memoryAnomaly,
}

// ── Permission Usage Model ─────────────────────────────────────────────────

class PermissionUsage {
  final String permissionName;
  final bool isDeclared;
  final bool isCurrentlyUsed;
  final bool isBackgroundAccess;
  final DateTime? lastUsed;
  final int usageCount;

  const PermissionUsage({
    required this.permissionName,
    required this.isDeclared,
    required this.isCurrentlyUsed,
    required this.isBackgroundAccess,
    this.lastUsed,
    required this.usageCount,
  });

  bool get isSuspicious => isCurrentlyUsed && isBackgroundAccess;
}

// ── Risk Score Model ───────────────────────────────────────────────────────

class RiskScore {
  final int score; // 0–100
  final RiskLevel level;
  // 6-category breakdown
  final double runtimeContribution; // system security sub-score
  final double networkContribution;
  final double permissionContribution;
  final double sensorContribution; // new
  final double appContribution; // new
  final double aggregatedContribution; // new
  final DateTime calculatedAt;

  const RiskScore({
    required this.score,
    required this.level,
    required this.runtimeContribution,
    required this.networkContribution,
    required this.permissionContribution,
    this.sensorContribution = 0,
    this.appContribution = 0,
    this.aggregatedContribution = 0,
    required this.calculatedAt,
  });

  static RiskScore get initial => RiskScore(
    score: 0,
    level: RiskLevel.safe,
    runtimeContribution: 0,
    networkContribution: 0,
    permissionContribution: 0,
    calculatedAt: DateTime.now(),
  );

  RiskLevel get computedLevel {
    if (score <= AppConstants.safeThreshold) return RiskLevel.safe;
    if (score <= AppConstants.suspiciousThreshold) return RiskLevel.suspicious;
    return RiskLevel.dangerous;
  }
}

// ── Scan Result ────────────────────────────────────────────────────────────

class ScanResult {
  final DateTime scanTime;
  final RiskScore riskScore;
  final List<AlertEvent> alerts;
  final List<NetworkConnection> connections;
  final List<PermissionUsage> permissions;
  final List<RuntimeEvent> runtimeEvents;
  final bool wasSuccessful;
  final String? errorMessage;

  const ScanResult({
    required this.scanTime,
    required this.riskScore,
    required this.alerts,
    required this.connections,
    required this.permissions,
    required this.runtimeEvents,
    required this.wasSuccessful,
    this.errorMessage,
  });
}

// ── App Scan Result Model ──────────────────────────────────────────────────

enum AppRiskLevel {
  safe,
  suspicious,
  malicious;

  String get label {
    switch (this) {
      case AppRiskLevel.safe:
        return 'SAFE';
      case AppRiskLevel.suspicious:
        return 'SUSPICIOUS';
      case AppRiskLevel.malicious:
        return 'MALICIOUS';
    }
  }
}

class ScannedApp {
  final String packageName;
  final String appName;
  final bool isSystemApp;
  final String installSource; // "play_store" | "sideloaded" | "other:xxx"
  final bool isSideloaded;
  final DateTime firstInstallTime;
  final DateTime lastUpdateTime;
  final int installDaysAgo;
  final bool isRecentInstall;
  final String versionName;
  final int targetSdkVersion;
  final List<String> allPermissions;
  final List<String> dangerousGranted; // DANGEROUS permissions actually granted
  final List<String> grantedHighRisk; // Subset: camera, mic, location, SMS etc.
  final double backgroundTimeHrs; // Real foreground/bg time from UsageStats
  final bool isCurrentlyRunning; // Real: from ActivityManager
  final int riskScore; // 0–100 computed by Kotlin
  final AppRiskLevel riskLevel; // SAFE / SUSPICIOUS / MALICIOUS
  final List<String> riskSignals; // Human-readable reasons

  const ScannedApp({
    required this.packageName,
    required this.appName,
    required this.isSystemApp,
    required this.installSource,
    required this.isSideloaded,
    required this.firstInstallTime,
    required this.lastUpdateTime,
    required this.installDaysAgo,
    required this.isRecentInstall,
    required this.versionName,
    required this.targetSdkVersion,
    required this.allPermissions,
    required this.dangerousGranted,
    required this.grantedHighRisk,
    required this.backgroundTimeHrs,
    required this.isCurrentlyRunning,
    required this.riskScore,
    required this.riskLevel,
    required this.riskSignals,
  });

  factory ScannedApp.fromMap(Map<String, dynamic> m) {
    final levelStr = m['riskLevel'] as String? ?? 'SAFE';
    final level = switch (levelStr) {
      'MALICIOUS' => AppRiskLevel.malicious,
      'SUSPICIOUS' => AppRiskLevel.suspicious,
      _ => AppRiskLevel.safe,
    };
    return ScannedApp(
      packageName: m['packageName'] as String? ?? '',
      appName: m['appName'] as String? ?? '',
      isSystemApp: m['isSystemApp'] as bool? ?? false,
      installSource: m['installSource'] as String? ?? 'unknown',
      isSideloaded: m['isSideloaded'] as bool? ?? false,
      firstInstallTime: DateTime.fromMillisecondsSinceEpoch(
        (m['firstInstallTime'] as num?)?.toInt() ?? 0,
      ),
      lastUpdateTime: DateTime.fromMillisecondsSinceEpoch(
        (m['lastUpdateTime'] as num?)?.toInt() ?? 0,
      ),
      installDaysAgo: (m['installDaysAgo'] as num?)?.toInt() ?? 0,
      isRecentInstall: m['isRecentInstall'] as bool? ?? false,
      versionName: m['versionName'] as String? ?? '',
      targetSdkVersion: (m['targetSdkVersion'] as num?)?.toInt() ?? 0,
      allPermissions: List<String>.from(m['allPermissions'] as List? ?? []),
      dangerousGranted: List<String>.from(m['dangerousGranted'] as List? ?? []),
      grantedHighRisk: List<String>.from(m['grantedHighRisk'] as List? ?? []),
      backgroundTimeHrs: (m['backgroundTimeHrs'] as num?)?.toDouble() ?? 0.0,
      isCurrentlyRunning: m['isCurrentlyRunning'] as bool? ?? false,
      riskScore: (m['riskScore'] as num?)?.toInt() ?? 0,
      riskLevel: level,
      riskSignals: List<String>.from(m['riskSignals'] as List? ?? []),
    );
  }
}

// ── App Network Usage Model ────────────────────────────────────────────────

class AppNetworkUsage {
  final String packageName;
  final String appName;
  final int txBytes;
  final int rxBytes;
  final int totalBytes;

  const AppNetworkUsage({
    required this.packageName,
    required this.appName,
    required this.txBytes,
    required this.rxBytes,
    required this.totalBytes,
  });

  factory AppNetworkUsage.fromMap(Map<String, dynamic> m) => AppNetworkUsage(
    packageName: m['packageName'] as String? ?? '',
    appName: m['appName'] as String? ?? '',
    txBytes: (m['txBytes'] as num?)?.toInt() ?? 0,
    rxBytes: (m['rxBytes'] as num?)?.toInt() ?? 0,
    totalBytes: (m['totalBytes'] as num?)?.toInt() ?? 0,
  );
}
