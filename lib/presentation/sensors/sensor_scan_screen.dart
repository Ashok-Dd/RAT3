import 'package:flutter/material.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// SensorScanScreen
///
/// Answers two simple questions:
///   Is the MICROPHONE currently in use by any app?
///   Is the CAMERA currently in use by any app?
///
/// Mic  → AudioManager.getActiveRecordingConfigurations() (API 24+)
///         Returns ALL active audio recording sessions system-wide.
///         If any session belongs to another app → mic is in use.
///
/// Camera → CameraManager.AvailabilityCallback
///           onCameraUnavailable fires for any camera held by any app.
///
/// Also lists which apps have the permission granted as "suspects".
class SensorScanScreen extends StatefulWidget {
  const SensorScanScreen({super.key});

  @override
  State<SensorScanScreen> createState() => _SensorScanScreenState();
}

class _SensorScanScreenState extends State<SensorScanScreen> {
  final _platform = PlatformChannelService();

  bool _loading = false;
  String? _error;

  bool _isMicInUse = false;
  bool _isCameraInUse = false;
  List<Map<String, dynamic>> _suspectApps = [];

  List<_PermApp> _cameraApps = [];
  List<_PermApp> _micApps = [];
  List<_PermApp> _locationApps = [];

  DateTime? _lastScanned;

  // Only show apps that were installed by the user —
  // not pre-loaded system apps, not ROM components.
  // We use the isSystemApp flag from Kotlin (FLAG_SYSTEM check)
  // plus a small blocklist for updated system apps that slip through.
  static const _selfPkg = AppConstants.selfPackageName;
  static const List<String> _alwaysSkip = [
    // Google core services that are "updated system apps" but not user apps
    'com.google.android.gms',
    'com.google.android.gsf',
    'com.google.android.webview',
    'com.google.android.networkstack',
    'com.google.android.permissioncontroller',
    'com.google.android.ext.services',
    'com.google.android.ext.shared',
    'com.android.vending', // Play Store itself
  ];

  bool _isUserApp(Map<String, dynamic> raw) {
    final pkg = raw['packageName'] as String? ?? '';
    if (pkg == _selfPkg) return false;
    // Kotlin already filtered FLAG_SYSTEM apps, but double-check
    final isSystem = raw['isSystemApp'] as bool? ?? false;
    if (isSystem) return false;
    // Block known Google infrastructure packages
    if (_alwaysSkip.any((s) => pkg == s || pkg.startsWith('$s.'))) return false;
    return true;
  }

  @override
  void initState() {
    super.initState();
    _scan();
  }

  Future<void> _scan() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      // Hardware-level detection
      final status = await _platform.checkSensorInUse();
      _isMicInUse = status['isMicInUse'] as bool? ?? false;
      _isCameraInUse = status['isCameraInUse'] as bool? ?? false;
      final rawSuspects = status['suspectApps'] as List? ?? [];
      _suspectApps = rawSuspects
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();

      debugPrint('SENSOR: mic=$_isMicInUse camera=$_isCameraInUse');

      // Permission holders
      final rawApps = await _platform.getUserInstalledSensorApps();
      final cam = <_PermApp>[];
      final mic = <_PermApp>[];
      final loc = <_PermApp>[];

      for (final raw in rawApps) {
        final pkg = raw['packageName'] as String? ?? '';
        final name = raw['appName'] as String? ?? pkg;
        if (!_isUserApp(raw)) continue;
        final granted = List<String>.from(raw['grantedSensors'] as List? ?? []);
        final recentFg = raw['isCurrentlyRunning'] as bool? ?? false;
        if (granted.contains('android.permission.CAMERA')) {
          cam.add(_PermApp(pkg: pkg, name: name, recentFg: recentFg));
        }
        if (granted.contains('android.permission.RECORD_AUDIO')) {
          mic.add(_PermApp(pkg: pkg, name: name, recentFg: recentFg));
        }
        if (granted.contains('android.permission.ACCESS_FINE_LOCATION') ||
            granted.contains('android.permission.ACCESS_COARSE_LOCATION') ||
            granted.contains('android.permission.ACCESS_BACKGROUND_LOCATION')) {
          loc.add(_PermApp(pkg: pkg, name: name, recentFg: recentFg));
        }
      }

      cam.sort((a, b) => (b.recentFg ? 1 : 0).compareTo(a.recentFg ? 1 : 0));
      mic.sort((a, b) => (b.recentFg ? 1 : 0).compareTo(a.recentFg ? 1 : 0));
      loc.sort((a, b) => (b.recentFg ? 1 : 0).compareTo(a.recentFg ? 1 : 0));

      setState(() {
        _cameraApps = cam;
        _micApps = mic;
        _locationApps = loc;
        _lastScanned = DateTime.now();
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      appBar: AppBar(
        backgroundColor: AppTheme.backgroundPrimary,
        leading: IconButton(
          icon: const Icon(
            Icons.arrow_back_ios,
            color: AppTheme.neonGreen,
            size: 18,
          ),
          onPressed: () => Navigator.pop(context),
        ),
        title: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(
            color: AppTheme.neonCyan.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(4),
            border: Border.all(color: AppTheme.neonCyan.withValues(alpha: 0.4)),
          ),
          child: Text(
            'SENSOR SCAN',
            style: AppTheme.labelSmall.copyWith(
              color: AppTheme.neonCyan,
              letterSpacing: 2,
            ),
          ),
        ),
        actions: [
          if (_loading)
            const Padding(
              padding: EdgeInsets.only(right: 12),
              child: Center(
                child: SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: AppTheme.neonGreen,
                  ),
                ),
              ),
            )
          else
            IconButton(
              icon: const Icon(Icons.refresh, color: AppTheme.neonGreen),
              onPressed: _scan,
            ),
        ],
      ),
      body: _error != null ? _buildError() : _buildBody(),
    );
  }

  Widget _buildError() => Center(
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const Icon(Icons.error_outline, color: AppTheme.alertRed, size: 48),
        const SizedBox(height: 12),
        Text(
          _error ?? '',
          style: AppTheme.bodyMedium,
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 20),
        ElevatedButton(
          onPressed: _scan,
          style: ElevatedButton.styleFrom(backgroundColor: AppTheme.neonGreen),
          child: Text(
            'RETRY',
            style: AppTheme.labelSmall.copyWith(
              color: AppTheme.backgroundPrimary,
            ),
          ),
        ),
      ],
    ),
  );

  Widget _buildBody() {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 100),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Last scanned timestamp ───────────────────────────────────────
          if (_lastScanned != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Row(
                children: [
                  const Icon(
                    Icons.schedule,
                    size: 11,
                    color: AppTheme.textMuted,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    'Last scanned: ${_fmt(_lastScanned!)}  •  tap ↻ to rescan',
                    style: AppTheme.bodyMedium.copyWith(
                      color: AppTheme.textMuted,
                      fontSize: 10,
                    ),
                  ),
                ],
              ),
            ),

          // ── BIG STATUS CARDS ─────────────────────────────────────────────
          Row(
            children: [
              Expanded(
                child: _BigStatusCard(
                  icon: Icons.mic_rounded,
                  label: 'MICROPHONE',
                  isOn: _isMicInUse,
                  loading: _loading,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: _BigStatusCard(
                  icon: Icons.videocam_rounded,
                  label: 'CAMERA',
                  isOn: _isCameraInUse,
                  loading: _loading,
                ),
              ),
            ],
          ),

          const SizedBox(height: 20),

          // ── Suspect apps when hardware is active ─────────────────────────
          if ((_isMicInUse || _isCameraInUse) && _suspectApps.isNotEmpty) ...[
            _sectionLabel(
              Icons.warning_amber_rounded,
              'POSSIBLE CULPRITS',
              AppTheme.alertRed,
            ),
            const SizedBox(height: 4),
            Text(
              'The ${_isCameraInUse && _isMicInUse
                  ? "camera and mic are"
                  : _isCameraInUse
                  ? "camera is"
                  : "mic is"} '
              'ON right now. These apps have the permission — one of them is likely using it:',
              style: AppTheme.bodyMedium.copyWith(
                color: AppTheme.textMuted,
                fontSize: 11,
              ),
            ),
            const SizedBox(height: 8),
            ..._suspectApps.map(
              (s) => _SuspectTile(
                app: s,
                isCameraActive: _isCameraInUse,
                isMicActive: _isMicInUse,
                platform: _platform,
              ),
            ),
            const SizedBox(height: 20),
          ],

          // ── Show "not detected but here are permission holders" ───────────
          if (!_isMicInUse && !_isCameraInUse && !_loading) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppTheme.neonGreen.withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                  color: AppTheme.neonGreen.withValues(alpha: 0.3),
                ),
              ),
              child: Row(
                children: [
                  const Icon(
                    Icons.check_circle_outline,
                    color: AppTheme.neonGreen,
                    size: 20,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Neither camera nor microphone is in use by any app right now.',
                      style: AppTheme.bodyMedium.copyWith(
                        color: AppTheme.neonGreen.withValues(alpha: 0.9),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),
          ],

          // ── Permission holders ───────────────────────────────────────────
          if (_cameraApps.isNotEmpty) ...[
            _sectionLabel(
              Icons.videocam_rounded,
              'HAS CAMERA PERMISSION',
              _isCameraInUse ? AppTheme.alertRed : AppTheme.neonYellow,
            ),
            const SizedBox(height: 6),
            ..._cameraApps.map(
              (a) => _PermTile(app: a, hardwareOn: _isCameraInUse),
            ),
            const SizedBox(height: 16),
          ],

          if (_micApps.isNotEmpty) ...[
            _sectionLabel(
              Icons.mic_rounded,
              'HAS MICROPHONE PERMISSION',
              _isMicInUse ? AppTheme.alertOrange : AppTheme.neonYellow,
            ),
            const SizedBox(height: 6),
            ..._micApps.map((a) => _PermTile(app: a, hardwareOn: _isMicInUse)),
            const SizedBox(height: 16),
          ],

          if (_locationApps.isNotEmpty) ...[
            _sectionLabel(
              Icons.location_on_rounded,
              'HAS LOCATION PERMISSION',
              AppTheme.neonYellow,
            ),
            const SizedBox(height: 6),
            ..._locationApps.map((a) => _PermTile(app: a, hardwareOn: false)),
          ],
        ],
      ),
    );
  }

  Widget _sectionLabel(IconData icon, String title, Color color) => Padding(
    padding: const EdgeInsets.only(bottom: 2),
    child: Row(
      children: [
        Icon(icon, size: 12, color: color),
        const SizedBox(width: 6),
        Text(
          title,
          style: AppTheme.labelSmall.copyWith(
            color: color,
            letterSpacing: 1.2,
            fontWeight: FontWeight.w700,
          ),
        ),
      ],
    ),
  );

  String _fmt(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:'
      '${t.minute.toString().padLeft(2, '0')}:'
      '${t.second.toString().padLeft(2, '0')}';
}

// ── Big Status Card ────────────────────────────────────────────────────────

class _BigStatusCard extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool isOn;
  final bool loading;

  const _BigStatusCard({
    required this.icon,
    required this.label,
    required this.isOn,
    required this.loading,
  });

  @override
  Widget build(BuildContext context) {
    final color = loading
        ? AppTheme.textMuted
        : isOn
        ? AppTheme.alertRed
        : AppTheme.neonGreen;

    final statusText = loading
        ? 'CHECKING…'
        : isOn
        ? 'ON — IN USE'
        : 'OFF — NOT IN USE';

    return Container(
      padding: const EdgeInsets.symmetric(vertical: 22, horizontal: 12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.5), width: 1.5),
        boxShadow: isOn
            ? [BoxShadow(color: color.withValues(alpha: 0.25), blurRadius: 18)]
            : null,
      ),
      child: Column(
        children: [
          // Icon with glow ring when ON
          Stack(
            alignment: Alignment.center,
            children: [
              if (isOn)
                Container(
                  width: 52,
                  height: 52,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: color.withValues(alpha: 0.18),
                  ),
                ),
              Icon(icon, color: color, size: 32),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            label,
            style: AppTheme.labelSmall.copyWith(
              color: color,
              letterSpacing: 1.2,
              fontSize: 10,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 6),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(6),
              border: Border.all(color: color.withValues(alpha: 0.4)),
            ),
            child: Text(
              statusText,
              style: AppTheme.labelSmall.copyWith(
                color: color,
                fontSize: 10,
                fontWeight: FontWeight.w800,
                letterSpacing: 0.5,
              ),
              textAlign: TextAlign.center,
            ),
          ),
        ],
      ),
    );
  }
}

// ── Suspect Tile ──────────────────────────────────────────────────────────

class _SuspectTile extends StatelessWidget {
  final Map<String, dynamic> app;
  final bool isCameraActive;
  final bool isMicActive;
  final PlatformChannelService platform;
  const _SuspectTile({
    required this.app,
    required this.isCameraActive,
    required this.isMicActive,
    required this.platform,
  });

  @override
  Widget build(BuildContext context) {
    final name = app['appName'] as String? ?? '';
    final pkg = app['packageName'] as String? ?? '';
    final hasCamera = app['hasCameraGrant'] as bool? ?? false;
    final hasMic = app['hasMicGrant'] as bool? ?? false;
    final likely = app['isLikelyActive'] as bool? ?? false;
    // Exact per-UID match from AudioManager.getActiveRecordingConfigurations — a real
    // confirmation, not a guess. Camera has no equivalent per-UID API on Android, so a
    // camera match here is always "candidate", never "confirmed".
    final micConfirmed = (app['micConfirmed'] as bool? ?? false) && isMicActive;

    final parts = <String>[
      if (hasCamera && isCameraActive) 'camera',
      if (hasMic && isMicActive) 'mic',
    ];

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.backgroundCard,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: AppTheme.alertRed.withValues(alpha: 0.5),
          width: 1.5,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 8,
                height: 8,
                margin: const EdgeInsets.only(right: 10),
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: AppTheme.alertRed,
                  boxShadow: [
                    BoxShadow(
                      color: AppTheme.alertRed.withValues(alpha: 0.5),
                      blurRadius: 6,
                      spreadRadius: 1,
                    ),
                  ],
                ),
              ),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      micConfirmed
                          ? '$name is using the microphone right now'
                          : name,
                      style: AppTheme.bodyLarge.copyWith(
                        fontWeight: FontWeight.w600,
                        color: AppTheme.textPrimary,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                    Text(
                      pkg,
                      style: AppTheme.bodyMedium.copyWith(
                        color: AppTheme.textMuted,
                        fontSize: 10,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (parts.isNotEmpty)
                      Text(
                        micConfirmed
                            ? 'Confirmed — a real, live microphone session'
                            : 'Has ${parts.join(" + ")} permission',
                        style: AppTheme.bodyMedium.copyWith(
                          color: AppTheme.alertRed.withValues(alpha: 0.8),
                          fontSize: 10,
                        ),
                      ),
                  ],
                ),
              ),
              if (micConfirmed)
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 6,
                    vertical: 3,
                  ),
                  decoration: BoxDecoration(
                    color: AppTheme.alertRed.withValues(alpha: 0.18),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(
                      color: AppTheme.alertRed.withValues(alpha: 0.5),
                    ),
                  ),
                  child: Text(
                    'CONFIRMED',
                    style: AppTheme.labelSmall.copyWith(
                      color: AppTheme.alertRed,
                      fontSize: 8,
                    ),
                    textAlign: TextAlign.center,
                  ),
                )
              else if (likely)
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 6,
                    vertical: 3,
                  ),
                  decoration: BoxDecoration(
                    color: AppTheme.alertOrange.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(
                      color: AppTheme.alertOrange.withValues(alpha: 0.4),
                    ),
                  ),
                  child: Text(
                    'RECENTLY\nACTIVE',
                    style: AppTheme.labelSmall.copyWith(
                      color: AppTheme.alertOrange,
                      fontSize: 8,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ),
            ],
          ),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerRight,
            child: OutlinedButton.icon(
              onPressed: () async {
                final opened = await platform.openAppSystemSettings(pkg);
                if (!context.mounted || opened) return;
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Could not open App Info')),
                );
              },
              style: OutlinedButton.styleFrom(
                foregroundColor: AppTheme.alertRed,
                side: BorderSide(color: AppTheme.alertRed.withValues(alpha: 0.5)),
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                minimumSize: Size.zero,
                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
              icon: const Icon(Icons.settings_outlined, size: 14),
              label: const Text(
                'Open App Info to stop it',
                style: TextStyle(fontSize: 11),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Permission Tile ───────────────────────────────────────────────────────

class _PermTile extends StatelessWidget {
  final _PermApp app;
  final bool hardwareOn;
  const _PermTile({required this.app, required this.hardwareOn});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: AppTheme.backgroundCard,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: hardwareOn && app.recentFg
              ? AppTheme.alertOrange.withValues(alpha: 0.45)
              : AppTheme.borderColor,
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 6,
            height: 6,
            margin: const EdgeInsets.only(right: 10),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: hardwareOn && app.recentFg
                  ? AppTheme.alertOrange
                  : AppTheme.textMuted,
            ),
          ),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  app.name,
                  style: AppTheme.bodyMedium.copyWith(
                    fontWeight: FontWeight.w600,
                    color: AppTheme.textPrimary,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  app.pkg,
                  style: AppTheme.bodyMedium.copyWith(
                    color: AppTheme.textMuted,
                    fontSize: 10,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          if (app.recentFg)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: AppTheme.alertOrange.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                'RECENT FG',
                style: AppTheme.labelSmall.copyWith(
                  color: AppTheme.alertOrange,
                  fontSize: 8,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _PermApp {
  final String pkg, name;
  final bool recentFg;
  const _PermApp({
    required this.pkg,
    required this.name,
    required this.recentFg,
  });
}
