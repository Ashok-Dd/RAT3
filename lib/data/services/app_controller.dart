import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/notification_service.dart';
import 'package:rat3/data/services/platform_channel_service.dart';
import 'package:rat3/data/services/storage_service.dart';
import 'package:rat3/layers/alert_engine/alert_engine.dart';
import 'package:rat3/layers/network_monitor/network_monitor.dart';
import 'package:rat3/layers/permission_tracker/permission_tracker.dart';
import 'package:rat3/layers/risk_engine/risk_engine.dart';
import 'package:rat3/layers/runtime_monitor/runtime_monitor.dart';

/// AppController — top-level orchestrator.
///
/// Wires the PlatformChannelService into every layer so all data
/// flows from real Android APIs, not simulated values.
class AppController extends ChangeNotifier {
  static const String _tag = 'AppController';

  // ── Services ───────────────────────────────────────────────────────────────
  final StorageService storageService = StorageService();
  final NotificationService notificationService = NotificationService();
  final PlatformChannelService platformService = PlatformChannelService();

  // ── Layers ─────────────────────────────────────────────────────────────────
  late final RuntimeMonitor runtimeMonitor;
  late final NetworkMonitor networkMonitor;
  late final PermissionTracker permissionTracker;
  late final AlertEngine alertEngine;
  late final RiskEngine riskEngine;

  // ── State ──────────────────────────────────────────────────────────────────
  RiskScore _riskScore = RiskScore.initial;
  RiskScore get riskScore => _riskScore;

  List<AlertEvent> _alerts = [];
  List<AlertEvent> get alerts => _alerts;

  List<NetworkConnection> _connections = [];
  List<NetworkConnection> get connections => _connections;

  bool _isMonitoringEnabled = true;
  bool get isMonitoringEnabled => _isMonitoringEnabled;

  bool _isScanning = false;
  bool get isScanning => _isScanning;

  DateTime? _lastScanTime;
  DateTime? get lastScanTime => _lastScanTime;

  int _scanIntervalMinutes =
      AppConstants.defaultScanInterval; // loaded from storage in init()
  int get scanIntervalMinutes => _scanIntervalMinutes;

  bool _onboardingComplete = false;
  bool get onboardingComplete => _onboardingComplete;

  // Real app version/build, read from the platform (not hardcoded) — shown in
  // Settings > About. Falls back to the pubspec version if the platform
  // channel isn't available yet (e.g. very first frame).
  String _appVersion = '…';
  String get appVersion => _appVersion;

  bool get isReleaseBuild => kReleaseMode;

  Timer? _autoScanTimer;
  final List<StreamSubscription> _subs = [];

  // ── Initialization ─────────────────────────────────────────────────────────

  Future<void> init() async {
    try {
      AppLogger.info(_tag, 'Initializing RAT3 (real data mode)…');

      await storageService.init();
      await notificationService.init();

      _scanIntervalMinutes = storageService.loadScanInterval();
      _lastScanTime = storageService.loadLastScanTime();
      _isMonitoringEnabled = storageService.loadMonitoringEnabled();
      _onboardingComplete = storageService.loadOnboardingComplete();

      try {
        final info = await PackageInfo.fromPlatform();
        _appVersion = '${info.version}+${info.buildNumber}';
      } catch (e) {
        AppLogger.warning(_tag, 'Could not read PackageInfo: $e');
      }

      // Inject real PlatformChannelService into every layer
      runtimeMonitor = RuntimeMonitor(platform: platformService);
      networkMonitor = NetworkMonitor(platform: platformService);
      permissionTracker = PermissionTracker(platform: platformService);

      alertEngine = AlertEngine(
        notificationService: notificationService,
        storageService: storageService,
      );

      riskEngine = RiskEngine(
        platform: platformService,
        networkMonitor: networkMonitor,
        storageService: storageService,
        alertEngine: alertEngine,
      );

      // Wire all layer alert streams into the central Alert Engine
      alertEngine.init();
      alertEngine.subscribeToLayer(runtimeMonitor.alerts);
      alertEngine.subscribeToLayer(networkMonitor.alerts);
      alertEngine.subscribeToLayer(permissionTracker.alerts);

      // Subscribe UI state to streams
      _subs.add(alertEngine.alertStream.listen(_onAlertsUpdated));
      _subs.add(riskEngine.scoreStream.listen(_onScoreUpdated));
      _subs.add(networkMonitor.connections.listen(_onNewConnection));

      // Restore persisted alerts
      _alerts = alertEngine.allAlerts;

      // Only run monitoring once the user has been through the permission flow.
      if (_isMonitoringEnabled && _onboardingComplete) _startMonitoring();

      AppLogger.info(_tag, 'AppController initialized — all layers ready');
    } catch (e, st) {
      AppLogger.error(_tag, 'init failed', e, st);
    }
  }

  // ── Monitoring Lifecycle ───────────────────────────────────────────────────

  void _startMonitoring() {
    runtimeMonitor.start();
    networkMonitor.start();
    riskEngine.start();
    _scheduleAutoScan();
    // Start the native Android ForegroundService so scanning continues
    // even when the Flutter app is closed or swiped from recents.
    platformService.startForegroundService(
      intervalMinutes: _scanIntervalMinutes,
    );
    AppLogger.info(
      _tag,
      'All monitoring layers started (foreground service running)',
    );
    // Auto-scan immediately on startup so the dashboard never shows 0.
    // Small delay lets all layers fully initialise before the first scan.
    Future.delayed(const Duration(seconds: 2), () {
      if (_isMonitoringEnabled) performScan();
    });
  }

  void _stopMonitoring() {
    runtimeMonitor.stop();
    networkMonitor.stop();
    riskEngine.stop();
    _autoScanTimer?.cancel();
    // Stop the native foreground service
    platformService.stopForegroundService();
    notificationService.cancelAll();
    AppLogger.info(
      _tag,
      'All monitoring layers stopped (foreground service stopped)',
    );
  }

  Future<void> setMonitoringEnabled(bool enabled) async {
    _isMonitoringEnabled = enabled;
    await storageService.saveMonitoringEnabled(enabled);
    enabled ? _startMonitoring() : _stopMonitoring();
    notifyListeners();
  }

  // ── Auto-Scan Scheduling ───────────────────────────────────────────────────

  void _scheduleAutoScan() {
    _autoScanTimer?.cancel();
    _autoScanTimer = Timer.periodic(
      Duration(minutes: _scanIntervalMinutes),
      (_) => performScan(),
    );
    AppLogger.info(_tag, 'Auto-scan scheduled every $_scanIntervalMinutes min');
  }

  Future<void> setScanInterval(int minutes) async {
    _scanIntervalMinutes = minutes;
    await storageService.saveScanInterval(minutes);
    if (_isMonitoringEnabled) {
      // Re-schedule the Dart-side auto-scan timer at the new interval
      _scheduleAutoScan();
      // Send new interval to the native service — it is already running persistently.
      // onStartCommand receives the new interval, re-arms its Handler + AlarmManager
      // timers at the new interval. No stop/start needed — that would cause a gap
      // and trigger Android 12+ background-start restrictions.
      await platformService.startForegroundService(intervalMinutes: minutes);
    }
    notifyListeners();
  }

  // ── Manual / Auto Scan ────────────────────────────────────────────────────

  /// Runs a full real scan across all 3 layers in parallel.
  /// Clears all previous alerts first so the user always sees a fresh set.
  Future<void> performScan() async {
    if (_isScanning) return;
    _isScanning = true;
    notifyListeners();

    try {
      AppLogger.info(_tag, 'Starting full real scan — clearing old alerts…');
      // Clear all previous alerts AND connections so user always sees fresh results
      await alertEngine.resetForNewScan();
      _connections = [];
      notifyListeners();

      // Run all 3 layer scans in parallel for speed
      final results = await Future.wait([
        runtimeMonitor.performScan(),
        networkMonitor.performScan(),
        permissionTracker.performScan(),
      ]);

      final runtimeEvents = results[0] as List<RuntimeEvent>;
      final netConnections = results[1] as List<NetworkConnection>;
      // Permission results already emit their own alerts internally

      // Update connection list (newest first, bounded to 100)
      _connections = [
        ...netConnections,
        ..._connections.take(100 - netConnections.length),
      ];

      // Recalculate risk score using full feature engine
      await riskEngine.recalculate();

      _lastScanTime = DateTime.now();
      await storageService.saveLastScanTime(_lastScanTime!);

      AppLogger.info(
        _tag,
        'Real scan complete. '
        'Runtime events: ${runtimeEvents.length} | '
        'Connections: ${netConnections.length}',
      );
    } catch (e, st) {
      AppLogger.error(_tag, 'performScan error', e, st);
    } finally {
      _isScanning = false;
      notifyListeners();
    }
  }

  // ── Stream Callbacks ───────────────────────────────────────────────────────

  void _onAlertsUpdated(List<AlertEvent> alerts) {
    _alerts = alerts;
    notifyListeners();
  }

  void _onScoreUpdated(RiskScore score) {
    _riskScore = score;
    notifyListeners();
  }

  void _onNewConnection(NetworkConnection conn) {
    _connections = [conn, ..._connections.take(99)];
    notifyListeners();
  }

  // ── Settings ───────────────────────────────────────────────────────────────

  Future<void> resetRiskScore() async {
    await storageService.resetAll();
    _riskScore = RiskScore.initial;
    _alerts = [];
    _connections = [];
    notifyListeners();
    AppLogger.info(_tag, 'Risk score reset');
  }

  /// Called by [OnboardingScreen] once the user finishes (or skips) setup.
  Future<void> completeOnboarding() async {
    _onboardingComplete = true;
    await storageService.saveOnboardingComplete(true);
    if (_isMonitoringEnabled) _startMonitoring();
    notifyListeners();
  }

  Future<void> setNotificationsEnabled(bool enabled) async {
    alertEngine.setNotificationsEnabled(enabled);
    await storageService.saveNotificationsEnabled(enabled);
    notifyListeners();
  }

  bool get notificationsEnabled => storageService.loadNotificationsEnabled();

  // ── Disposal ───────────────────────────────────────────────────────────────

  @override
  void dispose() {
    for (final s in _subs) {
      s.cancel();
    }
    _stopMonitoring();
    alertEngine.dispose();
    runtimeMonitor.dispose();
    networkMonitor.dispose();
    permissionTracker.dispose();
    riskEngine.dispose();
    super.dispose();
  }
}
