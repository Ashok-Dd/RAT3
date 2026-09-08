import 'dart:math';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/widgets/common_widgets.dart';
import 'package:rat3/presentation/app_scan/app_scan_screen.dart';
import 'package:rat3/presentation/sensors/sensor_scan_screen.dart';

class ScannerScreen extends StatefulWidget {
  const ScannerScreen({super.key});

  @override
  State<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends State<ScannerScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _scanCtrl;
  late Animation<double> _scanRotation;

  // Tracks which scan step is currently active for the loader display
  int _currentStep = 0;
  static const List<String> _scanSteps = [
    'Initializing scan engine...',
    'Analyzing runtime behavior...',
    'Scanning network connections...',
    'Auditing permission usage...',
    'Calculating risk score...',
    'Finalizing results...',
  ];

  @override
  void initState() {
    super.initState();
    _scanCtrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    );
    _scanRotation = Tween<double>(begin: 0, end: 2 * pi).animate(
      CurvedAnimation(parent: _scanCtrl, curve: Curves.linear),
    );
  }

  @override
  void dispose() {
    _scanCtrl.dispose();
    super.dispose();
  }

  Future<void> _startScan(AppController ctrl) async {
    if (ctrl.isScanning) return;

    setState(() => _currentStep = 0);
    _scanCtrl.repeat();

    // Step through the loader messages while scan runs
    _tickSteps();

    await ctrl.performScan();

    _scanCtrl.stop();
    _scanCtrl.reset();
    setState(() => _currentStep = 0);
  }

  /// Advances the step label every ~600ms to give live feedback
  Future<void> _tickSteps() async {
    for (int i = 1; i < _scanSteps.length; i++) {
      await Future.delayed(const Duration(milliseconds: 600));
      if (mounted) setState(() => _currentStep = i);
    }
  }

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<AppController>();

    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 100),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildScanButton(ctrl),
            const SizedBox(height: 24),

            // ── Scan Loader (visible only while scanning) ──────────────────
            if (ctrl.isScanning) ...[
              _buildScanLoader(),
              const SizedBox(height: 24),
            ],

            _buildScanInterval(ctrl),
            const SizedBox(height: 24),
            _buildScanInfo(),
            const SizedBox(height: 24),
            _buildLayerStatus(ctrl),
            const SizedBox(height: 24),
            // Two deep-scan buttons side by side
            Row(children: 
            [
              
              Expanded(child: _buildNavButton(
                label: 'SENSOR SCAN',
                sub: 'Camera, mic & location access',
                icon: Icons.sensors,
                color: AppTheme.neonCyan,
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => const SensorScanScreen()),
                ),
              )),
            ]),
          ],
        ),
      ),
    );
  }

  Widget _buildNavButton({
    required String label,
    required String sub,
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 12),
        decoration: BoxDecoration(
          color: color.withOpacity(0.07),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withOpacity(0.55), width: 1.5),
          boxShadow: [BoxShadow(
              color: color.withOpacity(0.12), blurRadius: 14, spreadRadius: 1)],
        ),
        child: Column(children: [
          Icon(icon, color: color, size: 28),
          const SizedBox(height: 8),
          Text(label, style: AppTheme.labelSmall.copyWith(
              color: color, fontWeight: FontWeight.w800,
              letterSpacing: 1.5, fontSize: 11),
              textAlign: TextAlign.center),
          const SizedBox(height: 4),
          Text(sub, style: AppTheme.bodyMedium.copyWith(
              color: color.withOpacity(0.6), fontSize: 10),
              textAlign: TextAlign.center),
        ]),
      ),
    );
  }

  // ── Scan Button ──────────────────────────────────────────────────────────

  Widget _buildScanButton(AppController ctrl) {
    return Center(
      child: Column(
        children: [
          const SizedBox(height: 24),
          GestureDetector(
            onTap: ctrl.isScanning ? null : () => _startScan(ctrl),
            child: Stack(
              alignment: Alignment.center,
              children: [
                // Outer rotating ring
                AnimatedBuilder(
                  animation: _scanRotation,
                  builder: (_, __) => Transform.rotate(
                    angle: _scanRotation.value,
                    child: Container(
                      width: 160,
                      height: 160,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: ctrl.isScanning
                              ? AppTheme.neonGreen
                              : AppTheme.neonGreen.withOpacity(0.4),
                          width: ctrl.isScanning ? 2 : 1,
                        ),
                      ),
                      child: CustomPaint(painter: _RadarPainter()),
                    ),
                  ),
                ),

                // Pulsing glow when scanning
                if (ctrl.isScanning)
                  TweenAnimationBuilder<double>(
                    tween: Tween(begin: 0.1, end: 0.35),
                    duration: const Duration(milliseconds: 900),
                    builder: (_, v, __) => Container(
                      width: 175,
                      height: 175,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(
                            color: AppTheme.neonGreen.withOpacity(v),
                            blurRadius: 30,
                            spreadRadius: 8,
                          ),
                        ],
                      ),
                    ),
                  ),

                // Inner button
                Container(
                  width: 120,
                  height: 120,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: AppTheme.backgroundCard,
                    border: Border.all(
                      color: ctrl.isScanning
                          ? AppTheme.neonGreen
                          : AppTheme.borderColor,
                      width: 2,
                    ),
                    boxShadow: ctrl.isScanning
                        ? [
                            BoxShadow(
                              color: AppTheme.neonGreen.withOpacity(0.3),
                              blurRadius: 20,
                              spreadRadius: 5,
                            ),
                          ]
                        : null,
                  ),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      // Show circular progress indicator INSIDE button while scanning
                      if (ctrl.isScanning)
                        const SizedBox(
                          width: 32,
                          height: 32,
                          child: CircularProgressIndicator(
                            strokeWidth: 2.5,
                            color: AppTheme.neonGreen,
                          ),
                        )
                      else
                        const Icon(
                          Icons.play_arrow_rounded,
                          color: AppTheme.neonGreen,
                          size: 36,
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
          const SizedBox(height: 16),

          // Status text below button
          AnimatedSwitcher(
            duration: const Duration(milliseconds: 300),
            child: ctrl.isScanning
                ? Text(
                    _scanSteps[_currentStep],
                    key: ValueKey(_currentStep),
                    style:
                        AppTheme.bodyMedium.copyWith(color: AppTheme.neonGreen),
                    textAlign: TextAlign.center,
                  )
                : Text(
                    ctrl.lastScanTime != null
                        ? 'Last scan: ${AppFormatter.formatTimeAgo(ctrl.lastScanTime!)}'
                        : 'No scan performed yet',
                    style: AppTheme.bodyMedium,
                    textAlign: TextAlign.center,
                  ),
          ),
        ],
      ),
    );
  }

  // ── Scan Progress Loader ─────────────────────────────────────────────────

  Widget _buildScanLoader() {
    final progress = (_currentStep + 1) / _scanSteps.length;

    return CyberCard(
      borderColor: AppTheme.neonGreen.withOpacity(0.4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const ScanPulse(),
              const SizedBox(width: 10),
              Text(
                'SCAN IN PROGRESS',
                style: AppTheme.labelSmall.copyWith(
                  color: AppTheme.neonGreen,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 2,
                ),
              ),
              const Spacer(),
              Text(
                '${(progress * 100).toInt()}%',
                style: AppTheme.bodyLarge.copyWith(color: AppTheme.neonGreen),
              ),
            ],
          ),
          const SizedBox(height: 12),

          // Progress bar
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: TweenAnimationBuilder<double>(
              tween: Tween(begin: 0, end: progress),
              duration: const Duration(milliseconds: 400),
              builder: (_, v, __) => LinearProgressIndicator(
                value: v,
                minHeight: 6,
                backgroundColor: AppTheme.borderColor,
                valueColor:
                    const AlwaysStoppedAnimation(AppTheme.neonGreen),
              ),
            ),
          ),
          const SizedBox(height: 16),

          // Step list
          ..._scanSteps.asMap().entries.map((entry) {
            final idx = entry.key;
            final label = entry.value;
            final isDone = idx < _currentStep;
            final isActive = idx == _currentStep;

            return Padding(
              padding: const EdgeInsets.symmetric(vertical: 4),
              child: Row(
                children: [
                  SizedBox(
                    width: 18,
                    height: 18,
                    child: isDone
                        ? const Icon(Icons.check_circle,
                            size: 16, color: AppTheme.neonGreen)
                        : isActive
                            ? const SizedBox(
                                width: 14,
                                height: 14,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: AppTheme.neonGreen,
                                ),
                              )
                            : Container(
                                width: 8,
                                height: 8,
                                margin: const EdgeInsets.all(4),
                                decoration: const BoxDecoration(
                                  shape: BoxShape.circle,
                                  color: AppTheme.textMuted,
                                ),
                              ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      label,
                      style: AppTheme.bodyMedium.copyWith(
                        color: isDone || isActive
                            ? AppTheme.textPrimary
                            : AppTheme.textMuted,
                        fontWeight: isActive
                            ? FontWeight.w600
                            : FontWeight.w400,
                      ),
                    ),
                  ),
                  if (isDone)
                    Text('✓',
                        style: AppTheme.labelSmall
                            .copyWith(color: AppTheme.neonGreen)),
                ],
              ),
            );
          }),
        ],
      ),
    );
  }

  // ── Scan Interval Slider ─────────────────────────────────────────────────

  Widget _buildScanInterval(AppController ctrl) {
    final intervals = AppConstants.scanIntervals;
    final currentIdx = intervals.indexOf(ctrl.scanIntervalMinutes);
    final sliderVal = (currentIdx < 0 ? 0 : currentIdx).toDouble();

    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: 'Auto-Scan Interval'),
          const SizedBox(height: 16),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: intervals.map((m) {
              final isSelected = m == ctrl.scanIntervalMinutes;
              return Text(
                AppFormatter.formatDuration(m),
                style: AppTheme.labelSmall.copyWith(
                  color: isSelected ? AppTheme.neonGreen : AppTheme.textMuted,
                  fontWeight:
                      isSelected ? FontWeight.w700 : FontWeight.w400,
                ),
              );
            }).toList(),
          ),
          Slider(
            value: sliderVal,
            min: 0,
            max: (intervals.length - 1).toDouble(),
            divisions: intervals.length - 1,
            label: AppFormatter.formatDuration(ctrl.scanIntervalMinutes),
            onChanged: (v) => ctrl.setScanInterval(intervals[v.round()]),
          ),
          Center(
            child: Text(
              'Auto-scan every ${AppFormatter.formatDuration(ctrl.scanIntervalMinutes)}',
              style: AppTheme.bodyMedium.copyWith(color: AppTheme.neonGreen),
            ),
          ),
        ],
      ),
    );
  }

  // ── Scan Coverage ─────────────────────────────────────────────────────────
  // FIX: replaced Row with Expanded + flexible layout to prevent text overflow

  Widget _buildScanInfo() {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeader(title: 'Scan Coverage'),
          const SizedBox(height: 12),
          _infoRow('Runtime Behavior', 'CPU, Background, Services'),
          _infoRow('Network Traffic',  'Connections, Data uploads'),
          _infoRow('Permissions',      'Declared vs used'),
          _infoRow('Risk Score',       'Composite calculation'),
        ],
      ),
    );
  }

  /// FIX: uses Flexible on both label and detail to prevent overflow
  Widget _infoRow(String label, String detail) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.check_circle_outline,
              size: 14, color: AppTheme.neonGreen),
          const SizedBox(width: 10),
          Flexible(
            flex: 2,
            child: Text(label, style: AppTheme.bodyLarge),
          ),
          const SizedBox(width: 8),
          Flexible(
            flex: 3,
            child: Text(
              detail,
              style: AppTheme.bodyMedium,
              textAlign: TextAlign.right,
              overflow: TextOverflow.ellipsis,
              maxLines: 2,
            ),
          ),
        ],
      ),
    );
  }

  // ── Layer Status ──────────────────────────────────────────────────────────

  Widget _buildLayerStatus(AppController ctrl) {
    return CyberCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeader(
            title: 'Monitoring Layers',
            trailing: Switch(
              value: ctrl.isMonitoringEnabled,
              onChanged: ctrl.setMonitoringEnabled,
            ),
          ),
          const SizedBox(height: 12),
          _layerRow('Layer 1', 'Runtime Monitor',    ctrl.isMonitoringEnabled),
          _layerRow('Layer 2', 'Network Analyzer',   ctrl.isMonitoringEnabled),
          _layerRow('Layer 3', 'Permission Tracker', ctrl.isMonitoringEnabled),
          _layerRow('Layer 4', 'Alert Engine',       ctrl.isMonitoringEnabled),
          _layerRow('Layer 5', 'Risk Engine',        ctrl.isMonitoringEnabled),
        ],
      ),
    );
  }

  Widget _layerRow(String layer, String name, bool active) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: active ? AppTheme.neonGreen : AppTheme.textMuted,
              boxShadow: active
                  ? [BoxShadow(
                      color: AppTheme.neonGreen.withOpacity(0.5),
                      blurRadius: 4,
                      spreadRadius: 1,
                    )]
                  : null,
            ),
          ),
          const SizedBox(width: 12),
          Text(layer,
              style: AppTheme.labelSmall
                  .copyWith(color: AppTheme.neonGreen.withOpacity(0.7))),
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
    );
  }
}

// ── Radar Ring Painter ─────────────────────────────────────────────────────

class _RadarPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = AppTheme.neonGreen.withOpacity(0.3)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1;

    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2;

    for (int i = 0; i < 12; i++) {
      final angle  = (i / 12) * 2 * pi;
      final innerR = radius - 12;
      canvas.drawLine(
        Offset(center.dx + innerR * cos(angle), center.dy + innerR * sin(angle)),
        Offset(center.dx + radius * cos(angle), center.dy + radius * sin(angle)),
        paint,
      );
    }
  }

  @override
  bool shouldRepaint(_RadarPainter _) => false;
}