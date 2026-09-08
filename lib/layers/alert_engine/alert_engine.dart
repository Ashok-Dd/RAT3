import 'dart:async';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/notification_service.dart';
import 'package:rat3/data/services/storage_service.dart';

/// Layer 4 – Alert Engine
///
/// Deduplication strategy (3 tiers):
///
///  Tier 1 — Persistent dedup (session-level):
///    Alerts with the same ID are NEVER shown twice in the same session.
///    e.g. "USB debugging enabled" fires once and never again until app restart.
///
///  Tier 2 — Time-window dedup (same title, different source):
///    Same title seen again within the cooldown window → suppressed.
///    Cooldown varies by severity:
///      critical  → 30 minutes
///      high      → 20 minutes
///      medium    → 10 minutes
///      low       →  5 minutes
///
///  Tier 3 — Per-scan dedup (app scanner):
///    App scanner results are cleared before each scan and injected fresh.
///    Old app scan alerts are removed before new ones are added.
class AlertEngine {
  static const String _tag = 'AlertEngine';
  static const int _maxAlerts = 500;

  final NotificationService _notificationService;
  final StorageService _storageService;

  final _alertsController = StreamController<List<AlertEvent>>.broadcast();
  Stream<List<AlertEvent>> get alertStream => _alertsController.stream;

  final List<StreamSubscription<AlertEvent>> _subscriptions = [];

  final List<AlertEvent> _alerts = [];
  List<AlertEvent> get allAlerts => List.unmodifiable(_alerts);

  // Tier 1: IDs seen this session — never repeat
  final Set<String> _seenIds = {};

  // Tier 2: title → last seen time (for same-title dedup with cooldown)
  final Map<String, DateTime> _titleLastSeen = {};

  bool _notificationsEnabled = true;

  // Cooldown per severity (minutes)
  static const Map<AlertSeverity, int> _cooldownMinutes = {
    AlertSeverity.critical: 30,
    AlertSeverity.high:     20,
    AlertSeverity.medium:   10,
    AlertSeverity.low:       5,
  };

  AlertEngine({
    required NotificationService notificationService,
    required StorageService storageService,
  })  : _notificationService = notificationService,
        _storageService = storageService;

  void init() {
    _alerts.addAll(_storageService.loadAlerts());
    _notificationsEnabled = _storageService.loadNotificationsEnabled();
    // Pre-populate seenIds from stored alerts so we don't re-show on restart
    for (final a in _alerts) {
      _seenIds.add(a.id);
    }
    AppLogger.info(_tag,
        'Alert engine initialized — ${_alerts.length} stored, ${_seenIds.length} known IDs');
  }

  void subscribeToLayer(Stream<AlertEvent> layerAlerts) {
    final sub = layerAlerts.listen(
      _onIncomingAlert,
      onError: (Object e) => AppLogger.error(_tag, 'Layer stream error', e),
    );
    _subscriptions.add(sub);
  }

  void injectAlert(AlertEvent alert) => _onIncomingAlert(alert);

  /// Inject a batch of alerts from app scanner.
  /// Removes previous app-scanner alerts first to avoid stale duplicates.
  void injectAppScanAlerts(List<AlertEvent> alerts) {
    // Remove all old app scan alerts before inserting new ones
    _alerts.removeWhere((a) => a.source == 'App Scanner');

    // Clear app scan IDs from seenIds so new scan results always show
    _seenIds.removeWhere((id) =>
        id.startsWith('appscan_') || id.startsWith('appscan_'));

    // Inject each new alert through normal dedup pipeline
    for (final alert in alerts) {
      _onIncomingAlert(alert);
    }
  }

  void _onIncomingAlert(AlertEvent alert) {
    final now = DateTime.now();

    // ── Tier 1: ID-based dedup ─────────────────────────────────────────────
    // Exact same alert ID → suppress forever this session
    if (_seenIds.contains(alert.id)) {
      AppLogger.info(_tag, 'Suppressed [ID-dup]: ${alert.title}');
      return;
    }

    // ── Tier 2: Title + cooldown dedup ────────────────────────────────────
    final cooldown = _cooldownMinutes[alert.severity] ?? 10;
    final lastSeen = _titleLastSeen[alert.title];
    if (lastSeen != null &&
        now.difference(lastSeen).inMinutes < cooldown) {
      AppLogger.info(_tag,
          'Suppressed [cooldown ${cooldown}min]: ${alert.title}');
      return;
    }

    // ── Accept alert ───────────────────────────────────────────────────────
    _seenIds.add(alert.id);
    _titleLastSeen[alert.title] = now;

    _alerts.insert(0, alert);
    if (_alerts.length > _maxAlerts) {
      _alerts.removeRange(_maxAlerts, _alerts.length);
    }

    _storageService.saveAlerts(_alerts.take(100).toList());

    AppLogger.info(_tag,
        'Alert accepted [${alert.severity.label}]: ${alert.title}');

    if (!_alertsController.isClosed) {
      _alertsController.add(List.unmodifiable(_alerts));
    }

    if (_notificationsEnabled &&
        alert.severity.index >= AlertSeverity.medium.index) {
      _notificationService.showAlertNotification(alert);
    }
  }

  void setNotificationsEnabled(bool enabled) {
    _notificationsEnabled = enabled;
  }

  Future<void> clearAlerts() async {
    _alerts.clear();
    _seenIds.clear();
    _titleLastSeen.clear();
    await _storageService.saveAlerts([]);
    if (!_alertsController.isClosed) _alertsController.add([]);
    AppLogger.info(_tag, 'All alerts cleared');
  }

  /// Called at the START of every new scan.
  ///
  /// ONLY clears app-scan alerts + their IDs.
  /// Persistent device-state alerts (USB debug, root, dev options) are KEPT
  /// in _seenIds so they never repeat every scan — user sees them once.
  Future<void> resetForNewScan() async {
    // Remove only app-scan alerts from the visible list
    _alerts.removeWhere((a) =>
        a.source == 'App Scanner' || a.id.startsWith('appscan_'));

    // Clear only app-scan IDs — persistent device-state IDs stay
    _seenIds.removeWhere((id) => id.startsWith('appscan_'));

    // Clear title cooldown only for app-scan related titles
    _titleLastSeen.removeWhere((title, _) {
      final t = title.toLowerCase();
      return t.contains('suspicious') ||
             t.contains('malicious') ||
             t.contains('package') ||
             t.contains('permission risk') ||
             t.contains('app scan');
    });

    await _storageService.saveAlerts(_alerts.take(100).toList());
    if (!_alertsController.isClosed) {
      _alertsController.add(List.unmodifiable(_alerts));
    }
    AppLogger.info(_tag, 'Scan reset — app alerts cleared, device alerts preserved');
  }

  List<AlertEvent> getAlertsBySeverity(AlertSeverity severity) =>
      _alerts.where((a) => a.severity == severity).toList();

  int get criticalCount => _alerts
      .where((a) =>
          a.severity == AlertSeverity.critical ||
          a.severity == AlertSeverity.high)
      .length;

  void dispose() {
    for (final sub in _subscriptions) sub.cancel();
    _alertsController.close();
  }
}