import 'dart:convert';

import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Handles all local persistent storage operations.
/// Uses SharedPreferences as the backing store.
class StorageService {
  static const String _tag = 'StorageService';

  SharedPreferences? _prefs;

  /// Must be called once at startup before any other method.
  Future<void> init() async {
    try {
      _prefs = await SharedPreferences.getInstance();
      AppLogger.info(_tag, 'Storage initialized');
    } catch (e, st) {
      AppLogger.error(_tag, 'Failed to init storage', e, st);
    }
  }

  SharedPreferences get _store {
    assert(_prefs != null, 'StorageService.init() must be called first');
    return _prefs!;
  }

  // ── Scan Interval ──────────────────────────────────────────────────────────

  Future<void> saveScanInterval(int minutes) async {
    try {
      await _store.setInt(AppConstants.keyScanInterval, minutes);
    } catch (e) {
      AppLogger.error(_tag, 'saveScanInterval failed', e);
    }
  }

  int loadScanInterval() {
    try {
      return _store.getInt(AppConstants.keyScanInterval) ??
          AppConstants.defaultScanInterval;
    } catch (e) {
      AppLogger.error(_tag, 'loadScanInterval failed', e);
      return AppConstants.defaultScanInterval;
    }
  }

  // ── Last Scan Time ─────────────────────────────────────────────────────────

  Future<void> saveLastScanTime(DateTime time) async {
    try {
      await _store.setString(
        AppConstants.keyLastScanTime,
        time.toIso8601String(),
      );
    } catch (e) {
      AppLogger.error(_tag, 'saveLastScanTime failed', e);
    }
  }

  DateTime? loadLastScanTime() {
    try {
      final raw = _store.getString(AppConstants.keyLastScanTime);
      return raw != null ? DateTime.parse(raw) : null;
    } catch (e) {
      AppLogger.error(_tag, 'loadLastScanTime failed', e);
      return null;
    }
  }

  // ── Risk Score ─────────────────────────────────────────────────────────────

  Future<void> saveRiskScore(int score) async {
    try {
      await _store.setInt(AppConstants.keyRiskScore, score);
    } catch (e) {
      AppLogger.error(_tag, 'saveRiskScore failed', e);
    }
  }

  int loadRiskScore() {
    try {
      return _store.getInt(AppConstants.keyRiskScore) ?? 0;
    } catch (e) {
      AppLogger.error(_tag, 'loadRiskScore failed', e);
      return 0;
    }
  }

  // ── Monitoring Enabled ─────────────────────────────────────────────────────

  Future<void> saveMonitoringEnabled(bool enabled) async {
    try {
      await _store.setBool(AppConstants.keyMonitoringEnabled, enabled);
    } catch (e) {
      AppLogger.error(_tag, 'saveMonitoringEnabled failed', e);
    }
  }

  bool loadMonitoringEnabled() {
    try {
      return _store.getBool(AppConstants.keyMonitoringEnabled) ?? true;
    } catch (e) {
      AppLogger.error(_tag, 'loadMonitoringEnabled failed', e);
      return true;
    }
  }

  // ── Notifications Enabled ──────────────────────────────────────────────────

  Future<void> saveNotificationsEnabled(bool enabled) async {
    try {
      await _store.setBool(AppConstants.keyNotificationsEnabled, enabled);
    } catch (e) {
      AppLogger.error(_tag, 'saveNotificationsEnabled failed', e);
    }
  }

  bool loadNotificationsEnabled() {
    try {
      return _store.getBool(AppConstants.keyNotificationsEnabled) ?? true;
    } catch (e) {
      AppLogger.error(_tag, 'loadNotificationsEnabled failed', e);
      return true;
    }
  }

  // ── Onboarding ─────────────────────────────────────────────────────────────

  Future<void> saveOnboardingComplete(bool done) async {
    try {
      await _store.setBool('onboarding_complete', done);
    } catch (e) {
      AppLogger.error(_tag, 'saveOnboardingComplete failed', e);
    }
  }

  bool loadOnboardingComplete() {
    try {
      return _store.getBool('onboarding_complete') ?? false;
    } catch (e) {
      AppLogger.error(_tag, 'loadOnboardingComplete failed', e);
      return false;
    }
  }

  // ── Alerts ─────────────────────────────────────────────────────────────────

  Future<void> saveAlerts(List<AlertEvent> alerts) async {
    try {
      final encoded = jsonEncode(alerts.map((a) => a.toJson()).toList());
      await _store.setString('alerts_list', encoded);
    } catch (e) {
      AppLogger.error(_tag, 'saveAlerts failed', e);
    }
  }

  List<AlertEvent> loadAlerts() {
    try {
      final raw = _store.getString('alerts_list');
      if (raw == null) return [];
      final list = jsonDecode(raw) as List<dynamic>;
      return list
          .map((e) => AlertEvent.fromJson(e as Map<String, dynamic>))
          .toList();
    } catch (e) {
      AppLogger.error(_tag, 'loadAlerts failed', e);
      return [];
    }
  }

  // ── Reset ──────────────────────────────────────────────────────────────────

  Future<void> resetAll() async {
    try {
      await _store.remove(AppConstants.keyRiskScore);
      await _store.remove(AppConstants.keyLastScanTime);
      await _store.remove('alerts_list');
      AppLogger.info(_tag, 'Storage reset complete');
    } catch (e) {
      AppLogger.error(_tag, 'resetAll failed', e);
    }
  }
}
