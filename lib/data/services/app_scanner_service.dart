import 'dart:async';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// AppScannerService — orchestrates the full "Scan All Apps" workflow.
///
/// Data sources (ALL real, no simulation):
///   scanAllApps()       → Kotlin: permissions, install source, risk signals,
///                          usage stats, running process check
///   getAppNetworkUsage()→ Kotlin: real TX/RX per app via TrafficStats UID
///   getActiveSensors()  → Kotlin: real SensorManager hardware sensor list
///
/// Emits progress updates via stream so the UI can show a live progress bar.
class AppScannerService {
  static const String _tag = 'AppScannerService';

  final PlatformChannelService _platform;

  AppScannerService({required PlatformChannelService platform})
    : _platform = platform;

  // Progress stream: 0.0 → 1.0
  final _progressController = StreamController<double>.broadcast();
  Stream<double> get progress => _progressController.stream;

  // Status message stream for showing what step is running
  final _statusController = StreamController<String>.broadcast();
  Stream<String> get status => _statusController.stream;

  bool _isScanning = false;
  bool get isScanning => _isScanning;

  AppScanResult? _lastResult;
  AppScanResult? get lastResult => _lastResult;

  // ── Main Scan ──────────────────────────────────────────────────────────────

  Future<AppScanResult> runFullScan() async {
    if (_isScanning) {
      return _lastResult ?? AppScanResult.empty();
    }

    _isScanning = true;
    _emit(0.0, 'Initializing app scanner…');

    try {
      // Step 1: Scan all installed apps (heaviest operation — runs on Kotlin thread)
      _emit(0.1, 'Reading installed applications…');
      final rawApps = await _platform.scanAllApps();
      _emit(0.4, 'Analyzing permissions and risk signals…');

      final apps = rawApps.map(ScannedApp.fromMap).toList();
      AppLogger.info(_tag, 'Scanned ${apps.length} apps');

      // Step 2: Real per-app network usage
      _emit(0.55, 'Reading network data usage per app…');
      final rawNetUsage = await _platform.getAppNetworkUsage();
      final netUsage = rawNetUsage.map(AppNetworkUsage.fromMap).toList();
      AppLogger.info(
        _tag,
        'Network usage: ${netUsage.length} apps with traffic',
      );

      // Step 3: Real sensor list
      _emit(0.70, 'Enumerating device sensors…');
      final rawSensors = await _platform.getActiveSensors();
      AppLogger.info(_tag, 'Sensors found: ${rawSensors.length}');

      // Step 4: Cross-reference network heavy apps with scanned apps
      // Flag any app that has high data usage AND suspicious risk level
      _emit(0.80, 'Cross-referencing network and permission data…');
      final enrichedApps = _enrichWithNetworkData(apps, netUsage);

      // Step 5: Build alerts from real scan findings
      _emit(0.90, 'Generating security alerts…');
      final alerts = _buildAlerts(enrichedApps, netUsage);

      // Step 6: Categorize
      _emit(0.97, 'Finalizing results…');
      final malicious = enrichedApps
          .where((a) => a.riskLevel == AppRiskLevel.malicious)
          .toList();
      final suspicious = enrichedApps
          .where((a) => a.riskLevel == AppRiskLevel.suspicious)
          .toList();
      final safe = enrichedApps
          .where((a) => a.riskLevel == AppRiskLevel.safe)
          .toList();

      final result = AppScanResult(
        scannedAt: DateTime.now(),
        totalApps: enrichedApps.length,
        maliciousApps: malicious,
        suspiciousApps: suspicious,
        safeApps: safe,
        networkUsage: netUsage,
        sensorCount: rawSensors.length,
        alerts: alerts,
      );

      _lastResult = result;
      _emit(1.0, 'Scan complete');
      return result;
    } catch (e, st) {
      AppLogger.error(_tag, 'runFullScan failed', e, st);
      _emit(1.0, 'Scan failed: ${e.toString()}');
      return AppScanResult.empty();
    } finally {
      _isScanning = false;
    }
  }

  // ── Enrich apps with network data ─────────────────────────────────────────

  List<ScannedApp> _enrichWithNetworkData(
    List<ScannedApp> apps,
    List<AppNetworkUsage> netUsage,
  ) {
    // Build a lookup map
    final netMap = <String, AppNetworkUsage>{};
    for (final n in netUsage) {
      netMap[n.packageName] = n;
    }

    // Apps with very high unexplained data usage get risk score boost
    // We rebuild a modified list — ScannedApp is immutable so we recreate
    return apps.map((app) {
      final net = netMap[app.packageName];
      if (net == null) return app;

      // 50MB+ total data and already suspicious → escalate to malicious
      final highData = net.totalBytes > 50 * 1024 * 1024;
      if (highData && app.riskLevel == AppRiskLevel.suspicious) {
        final newSignals = [
          ...app.riskSignals,
          'High data usage: ${AppFormatter.formatBytes(net.totalBytes)} '
              '(${AppFormatter.formatBytes(net.txBytes)} sent)',
        ];
        // Rebuild with escalated risk
        return ScannedApp(
          packageName: app.packageName,
          appName: app.appName,
          isSystemApp: app.isSystemApp,
          installSource: app.installSource,
          isSideloaded: app.isSideloaded,
          firstInstallTime: app.firstInstallTime,
          lastUpdateTime: app.lastUpdateTime,
          installDaysAgo: app.installDaysAgo,
          isRecentInstall: app.isRecentInstall,
          versionName: app.versionName,
          targetSdkVersion: app.targetSdkVersion,
          allPermissions: app.allPermissions,
          dangerousGranted: app.dangerousGranted,
          grantedHighRisk: app.grantedHighRisk,
          backgroundTimeHrs: app.backgroundTimeHrs,
          isCurrentlyRunning: app.isCurrentlyRunning,
          riskScore: (app.riskScore + 20).clamp(0, 100),
          riskLevel: AppRiskLevel.malicious,
          riskSignals: newSignals,
        );
      }
      return app;
    }).toList();
  }

  // ── Build real activity-specific alerts ──────────────────────────────────
  //
  // Priority order:
  //   1. ACTIVE behavior (running + camera/mic/network RIGHT NOW) → critical
  //   2. Background process with risk signals → high
  //   3. Dangerous permission grants → high/medium
  //   4. Overall risk classification → medium/high
  //   5. Sideloaded apps summary → medium

  List<AlertEvent> _buildAlerts(
    List<ScannedApp> apps,
    List<AppNetworkUsage> netUsage,
  ) {
    final alerts = <AlertEvent>[];
    final now = DateTime.now();
    // Build net usage lookup by packageName
    final netMap = <String, AppNetworkUsage>{};
    for (final n in netUsage) {
      netMap[n.packageName] = n;
    }

    for (final app in apps) {
      final net = netMap[app.packageName];
      final hasCamera = app.dangerousGranted.contains(
        'android.permission.CAMERA',
      );
      final hasMic = app.dangerousGranted.contains(
        'android.permission.RECORD_AUDIO',
      );
      final netTx = net?.txBytes ?? 0;
      final isActive = app.isCurrentlyRunning;

      // ── ACTIVE BEHAVIOR: camera running right now ─────────────────────────
      if (isActive && hasCamera) {
        alerts.add(
          AlertEvent(
            id: 'appscan_cam_active_${app.packageName}',
            severity: AlertSeverity.critical,
            title: '🎥 Camera Active — "${app.appName}"',
            description:
                '"${app.appName}" is currently running and holds CAMERA permission',
            userFriendlyMessage:
                '⚠ WARNING: "${app.appName}" is running RIGHT NOW and has '
                'camera access. It may be taking photos or recording video '
                'silently without any visible indicator.\n'
                'Action: Settings → Apps → "${app.appName}" → Permissions → '
                'Revoke Camera.',
            timestamp: now,
            source: 'App Scanner',
          ),
        );
      }

      // ── ACTIVE BEHAVIOR: microphone running right now ─────────────────────
      if (isActive && hasMic) {
        alerts.add(
          AlertEvent(
            id: 'appscan_mic_active_${app.packageName}',
            severity: AlertSeverity.critical,
            title: '🎤 Microphone Active — "${app.appName}"',
            description:
                '"${app.appName}" is currently running and holds RECORD_AUDIO permission',
            userFriendlyMessage:
                '⚠ WARNING: "${app.appName}" is running RIGHT NOW and has '
                'microphone access. It may be recording audio or conversations '
                'silently in the background.\n'
                'Action: Settings → Apps → "${app.appName}" → Permissions → '
                'Revoke Microphone.',
            timestamp: now,
            source: 'App Scanner',
          ),
        );
      }

      // ── ACTIVE BEHAVIOR: sending data right now ───────────────────────────
      if (isActive && netTx > 512 * 1024) {
        final severity = netTx > 5 * 1024 * 1024
            ? AlertSeverity.critical
            : AlertSeverity.high;
        alerts.add(
          AlertEvent(
            id: 'appscan_net_active_${app.packageName}',
            severity: severity,
            title: '📡 Data Transmission — "${app.appName}"',
            description:
                '"${app.appName}" sent ${AppFormatter.formatBytes(netTx)} '
                'while running in background',
            userFriendlyMessage:
                '⚠ "${app.appName}" is running and has transmitted '
                '${AppFormatter.formatBytes(netTx)} of data. '
                'If you are not actively using this app, it is sending '
                'data without your interaction. This matches data '
                'exfiltration behavior.',
            timestamp: now,
            source: 'App Scanner',
          ),
        );
      }

      // ── ACTIVE BEHAVIOR: background process with no clear reason ─────────
      if (isActive &&
          app.riskLevel != AppRiskLevel.safe &&
          !hasCamera &&
          !hasMic &&
          netTx <= 512 * 1024) {
        alerts.add(
          AlertEvent(
            id: 'appscan_bgproc_${app.packageName}',
            severity: AlertSeverity.high,
            title: '⚙ Suspicious Background Process — "${app.appName}"',
            description:
                '"${app.appName}" is running in background '
                '(risk score ${app.riskScore}/100)',
            userFriendlyMessage:
                '"${app.appName}" has an active background process '
                'and was flagged ${app.riskLevel.label}. '
                '${app.riskSignals.isNotEmpty ? app.riskSignals.first : ""}',
            timestamp: now,
            source: 'App Scanner',
          ),
        );
      }

      // ── PERMISSION ALERTS ─────────────────────────────────────────────────
      if (app.dangerousGranted.contains('android.permission.READ_SMS')) {
        alerts.add(
          AlertEvent(
            id: 'appscan_sms_${app.packageName}',
            severity: AlertSeverity.high,
            title: '💬 SMS Read Access — "${app.appName}"',
            description: '${app.appName} can read all SMS messages',
            userFriendlyMessage:
                '"${app.appName}" can read your SMS messages including '
                'OTPs and bank transaction alerts. Revoke if not needed.',
            timestamp: now,
            source: 'App Scanner',
          ),
        );
      }

      if (app.dangerousGranted.contains(
        'android.permission.ACCESS_BACKGROUND_LOCATION',
      )) {
        alerts.add(
          AlertEvent(
            id: 'appscan_bgloc_${app.packageName}',
            severity: AlertSeverity.high,
            title: '📍 Background Location — "${app.appName}"',
            description: '${app.appName} tracks location when closed',
            userFriendlyMessage:
                '"${app.appName}" is tracking your GPS location at all '
                'times, even when you are not using the app.',
            timestamp: now,
            source: 'App Scanner',
          ),
        );
      }

      // ── OVERALL RISK (only if no active behavior already flagged) ─────────
      final alreadyFlagged = alerts.any(
        (a) =>
            a.id.contains(app.packageName) &&
            (a.id.contains('_active_') || a.id.contains('_bgproc_')),
      );

      if (!alreadyFlagged) {
        if (app.riskLevel == AppRiskLevel.malicious) {
          alerts.add(
            AlertEvent(
              id: 'appscan_malicious_${app.packageName}',
              severity: AlertSeverity.critical,
              title: '🔴 Malicious App — "${app.appName}"',
              description:
                  'Score ${app.riskScore}/100 | '
                  '${app.riskSignals.take(2).join(" | ")}',
              userFriendlyMessage:
                  '"${app.appName}" is classified as MALICIOUS '
                  '(score: ${app.riskScore}/100). '
                  '${app.riskSignals.isNotEmpty ? app.riskSignals.first : "Multiple risk signals"}. '
                  'Uninstall this app immediately.',
              timestamp: now,
              source: 'App Scanner',
            ),
          );
        } else if (app.riskLevel == AppRiskLevel.suspicious) {
          alerts.add(
            AlertEvent(
              id: 'appscan_suspicious_${app.packageName}',
              severity: AlertSeverity.high,
              title: '🟠 Suspicious App — "${app.appName}"',
              description:
                  'Score ${app.riskScore}/100 | '
                  '${app.riskSignals.take(2).join(" | ")}',
              userFriendlyMessage:
                  '"${app.appName}" shows suspicious characteristics '
                  '(score: ${app.riskScore}/100). '
                  '${app.riskSignals.isNotEmpty ? app.riskSignals.first : "Review this app"}.',
              timestamp: now,
              source: 'App Scanner',
            ),
          );
        }
      }
    }

    // ── Sideloaded apps summary ───────────────────────────────────────────
    final sideloaded = apps
        .where((a) => a.isSideloaded && !a.isSystemApp)
        .toList();
    if (sideloaded.isNotEmpty) {
      alerts.add(
        AlertEvent(
          id: 'appscan_sideloaded_summary',
          severity: AlertSeverity.medium,
          title: '📦 ${sideloaded.length} Sideloaded App(s)',
          description: sideloaded.map((a) => a.appName).join(', '),
          userFriendlyMessage:
              '${sideloaded.length} app(s) installed outside Play Store: '
              '${sideloaded.map((a) => a.appName).take(3).join(", ")}. '
              'These bypass Google Play Protect scanning.',
          timestamp: now,
          source: 'App Scanner',
        ),
      );
    }

    return alerts;
  }

  void _emit(double progress, String message) {
    AppLogger.info(_tag, '[${(progress * 100).toInt()}%] $message');
    if (!_progressController.isClosed) _progressController.add(progress);
    if (!_statusController.isClosed) _statusController.add(message);
  }

  void dispose() {
    _progressController.close();
    _statusController.close();
  }
}

// ── Scan Result Model ──────────────────────────────────────────────────────

class AppScanResult {
  final DateTime scannedAt;
  final int totalApps;
  final List<ScannedApp> maliciousApps;
  final List<ScannedApp> suspiciousApps;
  final List<ScannedApp> safeApps;
  final List<AppNetworkUsage> networkUsage;
  final int sensorCount;
  final List<AlertEvent> alerts;

  const AppScanResult({
    required this.scannedAt,
    required this.totalApps,
    required this.maliciousApps,
    required this.suspiciousApps,
    required this.safeApps,
    required this.networkUsage,
    required this.sensorCount,
    required this.alerts,
  });

  factory AppScanResult.empty() => AppScanResult(
    scannedAt: DateTime.now(),
    totalApps: 0,
    maliciousApps: [],
    suspiciousApps: [],
    safeApps: [],
    networkUsage: [],
    sensorCount: 0,
    alerts: [],
  );
}
