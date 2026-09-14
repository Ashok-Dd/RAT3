import 'dart:async';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// AppScannerService — orchestrates the full "Scan All Apps" workflow.
///
/// Data sources (ALL real, no simulation):
///   scanAllApps()        → Kotlin: the evidence-based Application Assessment
///                          engine (trust level + explainable evidence list,
///                          see MainActivity.handleScanAllApps' doc comment)
///   getAppNetworkUsage() → Kotlin: real TX/RX per app via TrafficStats UID
///   getActiveSensors()   → Kotlin: real SensorManager hardware sensor list
///
/// This service does NOT compute or escalate trust on the Dart side — that
/// correlation happens once, in Kotlin, so there is exactly one place that
/// decides "is this app concerning" instead of two disagreeing heuristics.
/// Alerts here are a direct, calm restatement of what Kotlin already found.
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
      _emit(0.4, 'Evaluating evidence for each app…');

      final apps = rawApps.map(ScannedApp.fromMap).toList();
      AppLogger.info(_tag, 'Scanned ${apps.length} apps');

      // Step 2: Real per-app network usage (supplementary info only — never
      // used to escalate trust; see the false-positive bug this replaced).
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

      // Step 4: Build alerts from the trust levels Kotlin already computed
      _emit(0.85, 'Generating security alerts…');
      final alerts = _buildAlerts(apps);

      // Step 5: Categorize
      _emit(0.97, 'Finalizing results…');
      final malicious = apps
          .where((a) => a.trustLevel == AppTrustLevel.maliciousIndicators)
          .toList();
      final suspicious = apps
          .where((a) => a.trustLevel == AppTrustLevel.suspicious)
          .toList();
      final needsReview = apps
          .where((a) => a.trustLevel == AppTrustLevel.needsReview)
          .toList();
      final trusted = apps
          .where(
            (a) =>
                a.trustLevel == AppTrustLevel.trusted ||
                a.trustLevel == AppTrustLevel.unknown,
          )
          .toList();

      final result = AppScanResult(
        scannedAt: DateTime.now(),
        totalApps: apps.length,
        maliciousApps: malicious,
        suspiciousApps: suspicious,
        needsReviewApps: needsReview,
        trustedApps: trusted,
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
      // Let the caller (AppScanScreen) see the real failure and show its error
      // view — silently returning an empty-but-"successful" result made a
      // genuine scan failure indistinguishable from "0 apps on this device".
      rethrow;
    } finally {
      _isScanning = false;
    }
  }

  // ── Build alerts from the evidence Kotlin already correlated ─────────────
  //
  // One alert per app that reached NEEDS_REVIEW or above — the severity and
  // wording map directly from AppTrustLevel + the app's own evidence list, so
  // there is no second scoring pass here that could disagree with Kotlin.
  // TRUSTED and UNKNOWN apps never generate an alert, regardless of how many
  // permissions they hold or how much data they've sent — that was the root
  // cause of the WhatsApp/PhonePe/Google Pay/YouTube false positives.

  List<AlertEvent> _buildAlerts(List<ScannedApp> apps) {
    final alerts = <AlertEvent>[];
    final now = DateTime.now();

    for (final app in apps) {
      final severity = switch (app.trustLevel) {
        AppTrustLevel.maliciousIndicators => AlertSeverity.critical,
        AppTrustLevel.suspicious => AlertSeverity.high,
        AppTrustLevel.needsReview => AlertSeverity.medium,
        AppTrustLevel.trusted || AppTrustLevel.unknown => null,
      };
      if (severity == null) continue;

      final evidenceLines = app.evidence.isEmpty
          ? app.trustReason
          : app.evidence.join('. ');

      alerts.add(
        AlertEvent(
          id: 'appscan_${app.trustLevel.name}_${app.packageName}',
          severity: severity,
          title: '${app.trustLevel.label} — "${app.appName}"',
          description: evidenceLines,
          userFriendlyMessage: '"${app.appName}": $evidenceLines',
          timestamp: now,
          source: 'App Scanner',
        ),
      );
    }

    // ── Sideloaded apps summary — factual, not alarming ───────────────────
    final sideloaded = apps
        .where((a) => a.isSideloaded && !a.isSystemApp)
        .toList();
    if (sideloaded.isNotEmpty) {
      alerts.add(
        AlertEvent(
          id: 'appscan_sideloaded_summary',
          severity: AlertSeverity.medium,
          title: '${sideloaded.length} app(s) installed outside Play Store',
          description: sideloaded.map((a) => a.appName).join(', '),
          userFriendlyMessage:
              '${sideloaded.length} app(s) were installed from outside '
              'Play Store: ${sideloaded.map((a) => a.appName).take(3).join(", ")}. '
              'This alone is not a problem — many legitimate apps and stores '
              'distribute this way — but these apps bypass Play Protect '
              'scanning, so it is worth knowing which ones they are.',
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
  final List<ScannedApp> needsReviewApps;
  final List<ScannedApp> trustedApps;
  final List<AppNetworkUsage> networkUsage;
  final int sensorCount;
  final List<AlertEvent> alerts;

  const AppScanResult({
    required this.scannedAt,
    required this.totalApps,
    required this.maliciousApps,
    required this.suspiciousApps,
    required this.needsReviewApps,
    required this.trustedApps,
    required this.networkUsage,
    required this.sensorCount,
    required this.alerts,
  });

  factory AppScanResult.empty() => AppScanResult(
    scannedAt: DateTime.now(),
    totalApps: 0,
    maliciousApps: [],
    suspiciousApps: [],
    needsReviewApps: [],
    trustedApps: [],
    networkUsage: [],
    sensorCount: 0,
    alerts: [],
  );
}
