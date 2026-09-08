import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';

import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/data/services/platform_channel_service.dart';
import 'package:rat3/widgets/common_widgets.dart';

/// First-run permission wizard. The device monitor needs several special-access
/// grants that a normal runtime prompt can't cover (usage access, battery
/// exemption), so we walk the user through them once.
class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen>
    with WidgetsBindingObserver {
  final _platform = PlatformChannelService();

  bool _notifications = false;
  bool _usageAccess = false;
  bool _batteryExempt = false;
  bool _sensors = false;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _refresh();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) _refresh();
  }

  Future<void> _refresh() async {
    final flags = await _platform.getSecurityFlags();
    final notif = await Permission.notification.status;
    final cam = await Permission.camera.status;
    if (!mounted) return;
    setState(() {
      _notifications = notif.isGranted;
      _usageAccess = flags['hasUsageStatsPermission'] == true;
      _batteryExempt = flags['isIgnoringBatteryOptimizations'] == true;
      _sensors = cam.isGranted;
    });
  }

  Future<void> _requestNotifications() async {
    await Permission.notification.request();
    await _refresh();
  }

  Future<void> _requestSensors() async {
    await [Permission.camera, Permission.microphone, Permission.location].request();
    await _refresh();
  }

  Future<void> _openUsageAccess() async {
    await _platform.openUsageAccessSettings();
  }

  Future<void> _requestBattery() async {
    await _platform.requestBatteryOptimizationExemption();
    await _refresh();
  }

  Future<void> _finish() async {
    setState(() => _busy = true);
    await context.read<AppController>().completeOnboarding();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 32, 20, 24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Icon(Icons.shield_moon_outlined, color: AppTheme.neonGreen, size: 30),
                  const SizedBox(width: 10),
                  Text('RAT3', style: AppTheme.displayLarge.copyWith(fontSize: 30)),
                ],
              ),
              const SizedBox(height: 8),
              Text(
                'Grant a few permissions so RAT3 can watch this device for '
                'spyware and remote-access-trojan behaviour.',
                style: AppTheme.bodyMedium,
              ),
              const SizedBox(height: 24),
              _PermTile(
                icon: Icons.notifications_active_outlined,
                title: 'Notifications',
                subtitle: 'Alert you the moment a threat is detected.',
                granted: _notifications,
                onGrant: _requestNotifications,
              ),
              _PermTile(
                icon: Icons.query_stats,
                title: 'Usage access',
                subtitle: 'See which apps run in the background and abuse sensors.',
                granted: _usageAccess,
                onGrant: _openUsageAccess,
              ),
              _PermTile(
                icon: Icons.battery_saver_outlined,
                title: 'Ignore battery optimisation',
                subtitle: 'Keep monitoring alive when the screen is off.',
                granted: _batteryExempt,
                onGrant: _requestBattery,
              ),
              _PermTile(
                icon: Icons.sensors,
                title: 'Camera / mic / location',
                subtitle: 'Detect when another app secretly uses your sensors.',
                granted: _sensors,
                onGrant: _requestSensors,
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: _busy ? null : _finish,
                  child: Text(
                    _notifications && _usageAccess && _batteryExempt && _sensors
                        ? 'START MONITORING'
                        : 'CONTINUE',
                  ),
                ),
              ),
              const SizedBox(height: 8),
              Center(
                child: TextButton(
                  onPressed: _busy ? null : _finish,
                  child: Text('Skip for now', style: AppTheme.bodyMedium),
                ),
              ),
              const SizedBox(height: 8),
              Text(
                'You can grant anything you skip later from Settings → Fix permissions. '
                'Unmet permissions just reduce what the monitor can see.',
                style: AppTheme.labelSmall,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _PermTile extends StatelessWidget {
  const _PermTile({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.granted,
    required this.onGrant,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final bool granted;
  final Future<void> Function() onGrant;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: CyberCard(
        borderColor: granted ? AppTheme.neonGreen.withValues(alpha: 0.4) : null,
        child: Row(
          children: [
            Icon(icon, color: granted ? AppTheme.neonGreen : AppTheme.textSecondary, size: 24),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: AppTheme.bodyLarge.copyWith(fontWeight: FontWeight.w600)),
                  const SizedBox(height: 2),
                  Text(subtitle, style: AppTheme.labelSmall),
                ],
              ),
            ),
            const SizedBox(width: 8),
            if (granted)
              const Icon(Icons.check_circle, color: AppTheme.neonGreen, size: 22)
            else
              TextButton(onPressed: onGrant, child: const Text('GRANT')),
          ],
        ),
      ),
    );
  }
}
