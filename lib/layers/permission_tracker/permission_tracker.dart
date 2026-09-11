import 'dart:async';

import 'package:permission_handler/permission_handler.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// Layer 3 – Permission Usage Tracker
///
/// Detects OTHER installed apps holding sensitive sensor permissions
/// (camera / microphone / location) that are actively using them or have
/// real background activity while holding them — and names the specific app
/// in the alert, e.g. `"WhatsApp" used the microphone while running in the
/// background`.
///
/// Data source: `PlatformChannelService.getUserInstalledSensorApps()`, which
/// returns real **per-app** data from AppOpsManager (is the camera/mic op
/// currently allowed for this UID) and UsageStatsManager (is this app in the
/// foreground right now / was it recently / how many background hours).
///
/// Previously this layer checked `permission_handler`'s status for *this*
/// app's own grants (RAT3 requests none of these for detection purposes) and
/// a permission-agnostic "how many apps used the phone a lot today" count —
/// neither of which can identify which other app holds which permission, so
/// every alert was generic ("an app may be...") even though the UI text
/// implied a specific culprit had been found. This rewrite uses the per-app
/// data the native layer already collects (also used by the "Scan All Apps"
/// / Sensor Scan screens) so the claim and the evidence finally match.
class PermissionTracker {
  static const String _tag = 'PermissionTracker';

  final PlatformChannelService _platform;

  PermissionTracker({required PlatformChannelService platform})
    : _platform = platform;

  final _permissionController =
      StreamController<List<PermissionUsage>>.broadcast();
  final _alertController = StreamController<AlertEvent>.broadcast();

  Stream<List<PermissionUsage>> get permissionUpdates =>
      _permissionController.stream;
  Stream<AlertEvent> get alerts => _alertController.stream;

  List<PermissionUsage> _lastUsageSnapshot = [];
  List<PermissionUsage> get lastSnapshot =>
      List.unmodifiable(_lastUsageSnapshot);

  // Background time beyond which a granted high-risk sensor permission is
  // treated as suspicious (same threshold the old heuristic used).
  static const double _backgroundHoursThreshold = 2.0;

  static const _camera = 'android.permission.CAMERA';
  static const _mic = 'android.permission.RECORD_AUDIO';
  static const _bgLocation = 'android.permission.ACCESS_BACKGROUND_LOCATION';

  // ── Real Scan ──────────────────────────────────────────────────────────────

  Future<List<PermissionUsage>> performScan() async {
    final rawApps = await _platform.getUserInstalledSensorApps();

    var cameraGranted = 0, cameraBgHeavy = 0;
    var micGranted = 0, micBgHeavy = 0;
    var locGranted = 0;
    var bgLocGranted = 0, bgLocBgHeavy = 0;

    for (final raw in rawApps) {
      final pkg = raw['packageName'] as String? ?? '';
      final appName = raw['appName'] as String? ?? pkg;
      if (pkg.isEmpty) continue;

      final sensors =
          (raw['grantedSensors'] as List?)?.cast<String>() ?? const [];
      final camActiveNow = raw['isCameraActiveNow'] as bool? ?? false;
      final micActiveNow = raw['isMicActiveNow'] as bool? ?? false;
      final bgHrs = (raw['backgroundTimeHrs'] as num?)?.toDouble() ?? 0.0;

      final hasCamera = sensors.contains(_camera);
      final hasMic = sensors.contains(_mic);
      final hasBgLocation = sensors.contains(_bgLocation);
      final hasAnyLocation = sensors.any((s) => s.contains('LOCATION'));

      if (hasCamera) cameraGranted++;
      if (hasMic) micGranted++;
      if (hasAnyLocation) locGranted++;
      if (hasBgLocation) bgLocGranted++;

      // Tier A — the strongest signal we have: this exact app is using the
      // camera/mic RIGHT NOW (AppOps op allowed + app in foreground).
      if (camActiveNow) {
        cameraBgHeavy++;
        _emit(
          id: 'perm_cam_active_$pkg',
          severity: AlertSeverity.high,
          title: 'Camera In Use',
          description: '"$appName" is actively using the camera.',
          userMessage:
              '"$appName" is using your camera right now. If you did not '
              'open it for this, close the app and review its permissions.',
        );
      }
      if (micActiveNow) {
        micBgHeavy++;
        _emit(
          id: 'perm_mic_active_$pkg',
          severity: AlertSeverity.high,
          title: 'Microphone In Use',
          description: '"$appName" is actively using the microphone.',
          userMessage:
              '"$appName" is using your microphone right now. If you did '
              'not open it for this, close the app and review its permissions.',
        );
      }

      // Tier B — holds a high-risk sensor permission AND has real, sustained
      // background time (a proxy for "ran without the user actively using it").
      if (bgHrs > _backgroundHoursThreshold) {
        if (hasCamera && !camActiveNow) {
          _emit(
            id: 'perm_cam_background_$pkg',
            severity: AlertSeverity.medium,
            title: 'Camera Permission + Heavy Background Use',
            description:
                '"$appName" holds camera access and has ${bgHrs.toStringAsFixed(1)}h '
                'of background activity.',
            userMessage:
                '"$appName" can access your camera and has been running in '
                'the background for ${bgHrs.toStringAsFixed(1)} hours. Review '
                'whether it needs camera access.',
          );
        }
        if (hasMic && !micActiveNow) {
          _emit(
            id: 'perm_mic_background_$pkg',
            severity: AlertSeverity.medium,
            title: 'Microphone Permission + Heavy Background Use',
            description:
                '"$appName" holds microphone access and has ${bgHrs.toStringAsFixed(1)}h '
                'of background activity.',
            userMessage:
                '"$appName" can access your microphone and has been running '
                'in the background for ${bgHrs.toStringAsFixed(1)} hours. '
                'Review whether it needs microphone access.',
          );
        }
        if (hasBgLocation) {
          bgLocBgHeavy++;
          _emit(
            id: 'perm_bgloc_background_$pkg',
            severity: AlertSeverity.medium,
            title: 'Background Location + Heavy Background Use',
            description:
                '"$appName" holds background location access and has '
                '${bgHrs.toStringAsFixed(1)}h of background activity.',
            userMessage:
                '"$appName" can track your location in the background and '
                'has been running for ${bgHrs.toStringAsFixed(1)} hours. '
                'Review whether it needs background location.',
          );
        }
      }
    }

    final usages = <PermissionUsage>[
      _summary('Camera', cameraGranted, cameraBgHeavy),
      _summary('Microphone', micGranted, micBgHeavy),
      _summary('Location', locGranted, 0),
      _summary('Location (Background)', bgLocGranted, bgLocBgHeavy),
      await _selfPermissionSummary(),
    ];

    AppLogger.info(
      _tag,
      'Scan: ${rawApps.length} apps checked — '
      'camera=$cameraGranted mic=$micGranted location=$locGranted bgLocation=$bgLocGranted',
    );

    _lastUsageSnapshot = usages;
    if (!_permissionController.isClosed) {
      _permissionController.add(usages);
    }
    return usages;
  }

  PermissionUsage _summary(String name, int grantedCount, int suspiciousCount) {
    return PermissionUsage(
      permissionName: name,
      isDeclared: grantedCount > 0,
      isCurrentlyUsed: grantedCount > 0,
      isBackgroundAccess: suspiciousCount > 0,
      lastUsed: suspiciousCount > 0 ? DateTime.now() : null,
      usageCount: grantedCount,
    );
  }

  /// This app's OWN runtime permission grants — informational only (shown for
  /// transparency), never used as evidence about a *different* app. Reads
  /// status only — never requests, so a routine background scan can't pop a
  /// permission dialog.
  Future<PermissionUsage> _selfPermissionSummary() async {
    try {
      final statuses = await Future.wait([
        Permission.camera.status,
        Permission.microphone.status,
        Permission.location.status,
      ]);
      final grantedCount = statuses.where((s) => s.isGranted).length;
      return PermissionUsage(
        permissionName: 'This App (RAT3)',
        isDeclared: true,
        isCurrentlyUsed: grantedCount > 0,
        isBackgroundAccess: false,
        usageCount: grantedCount,
      );
    } catch (e) {
      AppLogger.warning(_tag, 'Could not read own permission status: $e');
      return const PermissionUsage(
        permissionName: 'This App (RAT3)',
        isDeclared: false,
        isCurrentlyUsed: false,
        isBackgroundAccess: false,
        usageCount: 0,
      );
    }
  }

  // ── Alert Emission ─────────────────────────────────────────────────────────

  void _emit({
    required String id,
    required AlertSeverity severity,
    required String title,
    required String description,
    required String userMessage,
  }) {
    final alert = AlertEvent(
      id: id,
      severity: severity,
      title: title,
      description: description,
      userFriendlyMessage: userMessage,
      timestamp: DateTime.now(),
      source: 'Permission Tracker',
    );
    if (!_alertController.isClosed) _alertController.add(alert);
  }

  void dispose() {
    _permissionController.close();
    _alertController.close();
  }
}
