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

// ── Connection Evidence (real-time VPN-based connection monitor) ───────────

/// One assessment level for an observed network connection — process-level,
/// not "how much data did this app use". A single ordinary connection is
/// never flagged; see [ConnectionEvidence.assessment].
enum ConnectionAssessment {
  normal,
  investigate,
  suspicious;

  String get label {
    switch (this) {
      case ConnectionAssessment.normal:
        return 'NORMAL';
      case ConnectionAssessment.investigate:
        return 'NEEDS INVESTIGATION';
      case ConnectionAssessment.suspicious:
        return 'SUSPICIOUS';
    }
  }
}

/// A real observed connection from RatVpnService (Kotlin) — actual process,
/// remote IP/port/protocol, and connection persistence, not a byte-usage
/// summary. See `ConnectionMonitor` for the correlation rules that decide
/// [assessment].
class ConnectionEvidence {
  final String protocol; // "TCP" | "UDP"
  final String packageName;
  final String appName;
  final String remoteAddress;
  final int remotePort;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final int bytesSent;
  final int bytesReceived;
  final int packetCount;
  final int reconnectCount;
  final bool isActive;
  final ConnectionAssessment assessment;
  final List<String> reasons;

  const ConnectionEvidence({
    required this.protocol,
    required this.packageName,
    required this.appName,
    required this.remoteAddress,
    required this.remotePort,
    required this.firstSeen,
    required this.lastSeen,
    required this.bytesSent,
    required this.bytesReceived,
    required this.packetCount,
    required this.reconnectCount,
    required this.isActive,
    required this.assessment,
    required this.reasons,
  });

  Duration get duration => lastSeen.difference(firstSeen);

  /// Re-observed across enough consecutive polls to call it a persistent /
  /// repeated communication pattern, rather than a one-off request.
  bool get isPersistent => reconnectCount >= 2 || duration.inMinutes >= 2;

  factory ConnectionEvidence.fromMap(Map<String, dynamic> m) {
    return ConnectionEvidence(
      protocol: m['protocol'] as String? ?? 'TCP',
      packageName: m['packageName'] as String? ?? 'unknown',
      appName: m['appName'] as String? ?? 'Unknown',
      remoteAddress: m['remoteAddress'] as String? ?? '',
      remotePort: (m['remotePort'] as num?)?.toInt() ?? 0,
      firstSeen: DateTime.fromMillisecondsSinceEpoch(
        (m['firstSeenMs'] as num?)?.toInt() ?? 0,
      ),
      lastSeen: DateTime.fromMillisecondsSinceEpoch(
        (m['lastSeenMs'] as num?)?.toInt() ?? 0,
      ),
      bytesSent: (m['bytesSent'] as num?)?.toInt() ?? 0,
      bytesReceived: (m['bytesReceived'] as num?)?.toInt() ?? 0,
      packetCount: (m['packetCount'] as num?)?.toInt() ?? 0,
      reconnectCount: (m['reconnectCount'] as num?)?.toInt() ?? 0,
      isActive: m['isActive'] as bool? ?? false,
      // Assessment/reasons are filled in by ConnectionMonitor's correlation
      // pass, not the raw platform-channel map.
      assessment: ConnectionAssessment.normal,
      reasons: const [],
    );
  }

  ConnectionEvidence copyWith({
    ConnectionAssessment? assessment,
    List<String>? reasons,
  }) => ConnectionEvidence(
    protocol: protocol,
    packageName: packageName,
    appName: appName,
    remoteAddress: remoteAddress,
    remotePort: remotePort,
    firstSeen: firstSeen,
    lastSeen: lastSeen,
    bytesSent: bytesSent,
    bytesReceived: bytesReceived,
    packetCount: packetCount,
    reconnectCount: reconnectCount,
    isActive: isActive,
    assessment: assessment ?? this.assessment,
    reasons: reasons ?? this.reasons,
  );
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

/// Application Assessment — deliberately separate from the device-level
/// [RiskLevel]. An app's trust level answers "should I be concerned about
/// THIS app specifically", evidence-first, never from permission count or
/// network/background activity alone. See [ScannedApp.trustReason]/[evidence]
/// for why a given level was reached — every non-[trusted] verdict must be
/// explainable.
enum AppTrustLevel {
  trusted,
  unknown,
  needsReview,
  suspicious,
  maliciousIndicators;

  String get label {
    switch (this) {
      case AppTrustLevel.trusted:
        return 'TRUSTED';
      case AppTrustLevel.unknown:
        return 'UNKNOWN';
      case AppTrustLevel.needsReview:
        return 'NEEDS REVIEW';
      case AppTrustLevel.suspicious:
        return 'SUSPICIOUS';
      case AppTrustLevel.maliciousIndicators:
        return 'MALICIOUS INDICATORS';
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
  final int txBytes;
  final int rxBytes;
  final double backgroundTimeHrs; // Real foreground/bg time from UsageStats
  final bool isCurrentlyRunning; // Real: in foreground right now (UsageEvents)
  final AppTrustLevel trustLevel;
  final String trustReason; // One-line headline explaining the verdict
  final List<String> evidence; // Full "why flagged" list, empty if trusted
  final List<String> privateDataAccess; // SMS / notifications / on-screen content

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
    required this.txBytes,
    required this.rxBytes,
    required this.backgroundTimeHrs,
    required this.isCurrentlyRunning,
    required this.trustLevel,
    required this.trustReason,
    required this.evidence,
    required this.privateDataAccess,
  });

  factory ScannedApp.fromMap(Map<String, dynamic> m) {
    final levelStr = m['trustLevel'] as String? ?? 'UNKNOWN';
    final level = switch (levelStr) {
      'TRUSTED' => AppTrustLevel.trusted,
      'NEEDS_REVIEW' => AppTrustLevel.needsReview,
      'SUSPICIOUS' => AppTrustLevel.suspicious,
      'MALICIOUS_INDICATORS' => AppTrustLevel.maliciousIndicators,
      _ => AppTrustLevel.unknown,
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
      txBytes: (m['txBytes'] as num?)?.toInt() ?? 0,
      rxBytes: (m['rxBytes'] as num?)?.toInt() ?? 0,
      backgroundTimeHrs: (m['backgroundTimeHrs'] as num?)?.toDouble() ?? 0.0,
      isCurrentlyRunning: m['isCurrentlyRunning'] as bool? ?? false,
      trustLevel: level,
      trustReason: m['trustReason'] as String? ?? '',
      evidence: List<String>.from(m['evidence'] as List? ?? []),
      privateDataAccess: List<String>.from(
        m['privateDataAccess'] as List? ?? [],
      ),
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
