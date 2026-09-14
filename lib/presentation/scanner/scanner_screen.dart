import 'dart:async';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/features/apk_scan/apk_scan_landing.dart';
import 'package:rat3/presentation/app_scan/app_scan_screen.dart';
import 'package:rat3/presentation/sensors/sensor_scan_screen.dart';
import 'package:rat3/presentation/trusted_apps/trusted_apps_screen.dart';
import 'package:rat3/widgets/common_widgets.dart';

enum _Mode { monitor, apk }

/// Scanner tab. A segmented control switches between the live device monitor
/// and the pre-installation APK scanner.
class ScannerScreen extends StatefulWidget {
  const ScannerScreen({super.key});

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen> {
  _Mode _mode = _Mode.monitor;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: SegmentedButton<_Mode>(
            segments: const [
              ButtonSegment(
                value: _Mode.monitor,
                label: Text('Device Monitor'),
                icon: Icon(Icons.radar),
              ),
              ButtonSegment(
                value: _Mode.apk,
                label: Text('Scan an APK'),
                icon: Icon(Icons.android),
              ),
            ],
            selected: {_mode},
            onSelectionChanged: (s) => setState(() => _mode = s.first),
            showSelectedIcon: false,
          ),
        ),
        Expanded(
          child: _mode == _Mode.monitor
              ? const _DeviceMonitorView()
              : const ApkScanLanding(),
        ),
      ],
    );
  }
}

// ── Device monitor pane ─────────────────────────────────────────────────────

class _DeviceMonitorView extends StatefulWidget {
  const _DeviceMonitorView();

  @override
  State<_DeviceMonitorView> createState() => _DeviceMonitorViewState();
}

class _DeviceMonitorViewState extends State<_DeviceMonitorView>
    with SingleTickerProviderStateMixin {
  late final AnimationController _radar = AnimationController(
    vsync: this,
    duration: const Duration(seconds: 2),
  );

  int _step = 0;
  static const _steps = [
    'Initializing scan engine…',
    'Analyzing runtime behavior…',
    'Scanning network connections…',
    'Auditing permission usage…',
    'Calculating risk score…',
  ];

  @override
  void dispose() {
    _radar.dispose();
    super.dispose();
  }

  Future<void> _scan(AppController ctrl) async {
    if (ctrl.isScanning) return;
    setState(() => _step = 0);
    unawaited(_radar.repeat());
    unawaited(_tick());
    await ctrl.performScan();
    if (!mounted) return;
    _radar
      ..stop()
      ..reset();
    setState(() => _step = 0);
  }

  Future<void> _tick() async {
    for (var i = 1; i < _steps.length; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 550));
      if (mounted) setState(() => _step = i);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<AppController>();
    return SingleChildScrollView(
      padding: AppTheme.pagePadding,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _scanButton(ctrl),
          const SizedBox(height: 24),
          _intervalCard(ctrl),
          const SizedBox(height: 16),
          _layerStatus(ctrl),
          const SizedBox(height: 16),
          _deepScans(),
        ],
      ),
    );
  }

  Widget _scanButton(AppController ctrl) {
    return Center(
      child: Column(
        children: [
          const SizedBox(height: 8),
          GestureDetector(
            onTap: ctrl.isScanning ? null : () => _scan(ctrl),
            child: Stack(
              alignment: Alignment.center,
              children: [
                AnimatedBuilder(
                  animation: _radar,
                  builder: (_, _) => Transform.rotate(
                    angle: _radar.value * 2 * pi,
                    child: Container(
                      width: 150,
                      height: 150,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: AppTheme.neonGreen.withValues(
                            alpha: ctrl.isScanning ? 1 : 0.4,
                          ),
                          width: ctrl.isScanning ? 2 : 1,
                        ),
                      ),
                      child: CustomPaint(painter: _RadarPainter()),
                    ),
                  ),
                ),
                Container(
                  width: 112,
                  height: 112,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: AppTheme.backgroundCard,
                    border: Border.all(
                      color: ctrl.isScanning
                          ? AppTheme.neonGreen
                          : AppTheme.borderColor,
                      width: 2,
                    ),
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      if (ctrl.isScanning)
                        const SizedBox(
                          width: 30,
                          height: 30,
                          child: CircularProgressIndicator(
                            strokeWidth: 2.5,
                            color: AppTheme.neonGreen,
                          ),
                        )
                      else
                        const Icon(
                          Icons.play_arrow_rounded,
                          color: AppTheme.neonGreen,
                          size: 34,
                        ),
                      const SizedBox(height: 6),
                      Text(
                        ctrl.isScanning ? 'SCANNING' : 'SCAN NOW',
                        style: AppTheme.labelSmall.copyWith(
                          color: AppTheme.neonGreen,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          Text(
            ctrl.isScanning
                ? _steps[_step]
                : ctrl.lastScanTime != null
                ? 'Last scan: ${AppFormatter.formatTimeAgo(ctrl.lastScanTime!)}'
                : 'No scan performed yet',
            style: AppTheme.bodyMedium.copyWith(
              color: ctrl.isScanning
                  ? AppTheme.neonGreen
                  : AppTheme.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _intervalCard(AppController ctrl) {
    final intervals = AppConstants.scanIntervals;
    final idx = intervals
        .indexOf(ctrl.scanIntervalMinutes)
        .clamp(0, intervals.length - 1);
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: 'Auto-Scan Interval'),
          const SizedBox(height: 8),
          Slider(
            value: idx.toDouble(),
            max: (intervals.length - 1).toDouble(),
            divisions: intervals.length - 1,
            label: AppFormatter.formatDuration(ctrl.scanIntervalMinutes),
            onChanged: (v) => ctrl.setScanInterval(intervals[v.round()]),
          ),
          Center(
            child: Text(
              'Every ${AppFormatter.formatDuration(ctrl.scanIntervalMinutes)} — even when the app is closed',
              style: AppTheme.bodyMedium.copyWith(color: AppTheme.neonGreen),
            ),
          ),
        ],
      ),
    );
  }

  Widget _layerStatus(AppController ctrl) {
    const layers = [
      ('Layer 1', 'Runtime Monitor'),
      ('Layer 2', 'Network Analyzer'),
      ('Layer 3', 'Permission Tracker'),
      ('Layer 4', 'Alert Engine'),
      ('Layer 5', 'Risk Engine'),
    ];
    final active = ctrl.isMonitoringEnabled;
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeader(
            title: 'Monitoring Layers',
            trailing: Switch(
              value: active,
              onChanged: ctrl.setMonitoringEnabled,
            ),
          ),
          const SizedBox(height: 8),
          for (final (tag, name) in layers)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 7),
              child: Row(
                children: [
                  Container(
                    width: 8,
                    height: 8,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: active ? AppTheme.neonGreen : AppTheme.textMuted,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Text(
                    tag,
                    style: AppTheme.labelSmall.copyWith(
                      color: AppTheme.neonGreen,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(child: Text(name, style: AppTheme.bodyMedium)),
                  Text(
                    active ? 'RUNNING' : 'IDLE',
                    style: AppTheme.labelSmall.copyWith(
                      color: active ? AppTheme.neonGreen : AppTheme.textMuted,
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }

  Widget _deepScans() {
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: _navCard(
                'SENSOR SCAN',
                'Camera, mic & location',
                Icons.sensors,
                () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => const SensorScanScreen(),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _navCard(
                'SCAN ALL APPS',
                'Audit every installed app',
                Icons.apps,
                () => Navigator.of(context).push(
                  MaterialPageRoute<void>(builder: (_) => const AppScanScreen()),
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        _navCard(
          'TRUSTED APPS',
          'Toggle which apps RAT3 skips scanning',
          Icons.verified_user_outlined,
          () => Navigator.of(context).push(
            MaterialPageRoute<void>(builder: (_) => const TrustedAppsScreen()),
          ),
          fullWidth: true,
        ),
      ],
    );
  }

  Widget _navCard(
    String label,
    String sub,
    IconData icon,
    VoidCallback onTap, {
    bool fullWidth = false,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 12),
        decoration: BoxDecoration(
          color: AppTheme.neonCyan.withValues(alpha: 0.07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppTheme.neonCyan.withValues(alpha: 0.5)),
        ),
        child: fullWidth
            ? Row(
                children: [
                  Icon(icon, color: AppTheme.neonCyan, size: 26),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          label,
                          style: AppTheme.labelSmall.copyWith(
                            color: AppTheme.neonCyan,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        const SizedBox(height: 2),
                        Text(sub, style: AppTheme.labelSmall),
                      ],
                    ),
                  ),
                  const Icon(
                    Icons.chevron_right,
                    color: AppTheme.neonCyan,
                    size: 20,
                  ),
                ],
              )
            : Column(
                children: [
                  Icon(icon, color: AppTheme.neonCyan, size: 26),
                  const SizedBox(height: 8),
                  Text(
                    label,
                    style: AppTheme.labelSmall.copyWith(
                      color: AppTheme.neonCyan,
                      fontWeight: FontWeight.w800,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    sub,
                    style: AppTheme.labelSmall,
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
      ),
    );
  }
}

class _RadarPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = AppTheme.neonGreen.withValues(alpha: 0.3)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2;
    for (var i = 0; i < 12; i++) {
      final angle = (i / 12) * 2 * pi;
      final inner = radius - 12;
      canvas.drawLine(
        Offset(center.dx + inner * cos(angle), center.dy + inner * sin(angle)),
        Offset(
          center.dx + radius * cos(angle),
          center.dy + radius * sin(angle),
        ),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(_RadarPainter oldDelegate) => false;
}
