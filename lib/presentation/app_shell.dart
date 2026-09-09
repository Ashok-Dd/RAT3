import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/features/apk_scan/scanning_screen.dart';
import 'package:rat3/features/apk_scan/services/apk_scanner_service.dart';
import 'package:rat3/presentation/alerts/alerts_screen.dart';
import 'package:rat3/presentation/dashboard/dashboard_screen.dart';
import 'package:rat3/presentation/network/network_screen.dart';
import 'package:rat3/presentation/scanner/scanner_screen.dart';
import 'package:rat3/presentation/settings/settings_screen.dart';

/// Root scaffold: five-tab bottom navigation for the device monitor, with the
/// pre-installation APK scanner folded into the "Scanner" tab.
class AppShell extends StatefulWidget {
  const AppShell({super.key});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  int _index = 0;

  static const _tabs = [
    (
      label: 'Dashboard',
      icon: Icons.shield_outlined,
      screen: DashboardScreen(),
    ),
    (label: 'Network', icon: Icons.wifi_outlined, screen: NetworkScreen()),
    (
      label: 'Alerts',
      icon: Icons.notifications_none_rounded,
      screen: AlertsScreen(),
    ),
    (label: 'Scanner', icon: Icons.radar_outlined, screen: ScannerScreen()),
    (
      label: 'Settings',
      icon: Icons.settings_outlined,
      screen: SettingsScreen(),
    ),
  ];

  @override
  void initState() {
    super.initState();
    // "Scan with RAT3" from a file manager routes straight into an APK scan.
    ApkScannerService().onIncomingApk = _openApkScan;
  }

  @override
  void dispose() {
    if (ApkScannerService().onIncomingApk == _openApkScan) {
      ApkScannerService().onIncomingApk = null;
    }
    super.dispose();
  }

  void _openApkScan(String path) {
    if (!mounted) return;
    Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => ApkScanningScreen(apkPath: path)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final criticalCount = context.select<AppController, int>(
      (c) => c.alertEngine.criticalCount,
    );
    final scanning = context.select<AppController, bool>((c) => c.isScanning);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 16,
        title: _brandChip(),
        actions: [
          if (scanning)
            const Padding(
              padding: EdgeInsets.only(right: 16),
              child: Center(
                child: SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: AppTheme.neonGreen,
                  ),
                ),
              ),
            ),
        ],
        bottom: const PreferredSize(
          preferredSize: Size.fromHeight(1),
          child: NeonDividerBar(),
        ),
      ),
      body: IndexedStack(
        index: _index,
        children: _tabs.map((t) => t.screen).toList(),
      ),
      bottomNavigationBar: _bottomBar(criticalCount),
    );
  }

  Widget _brandChip() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: AppTheme.neonGreen.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: AppTheme.neonGreen.withValues(alpha: 0.4)),
      ),
      child: Text(
        '🛡  RAT3',
        style: AppTheme.headlineLarge.copyWith(
          fontSize: 15,
          color: AppTheme.neonGreen,
        ),
      ),
    );
  }

  Widget _bottomBar(int criticalCount) {
    return Container(
      decoration: const BoxDecoration(
        color: AppTheme.backgroundSecondary,
        border: Border(top: BorderSide(color: AppTheme.borderColor)),
      ),
      child: BottomNavigationBar(
        currentIndex: _index,
        onTap: (i) => setState(() => _index = i),
        backgroundColor: Colors.transparent,
        elevation: 0,
        items: [
          for (var i = 0; i < _tabs.length; i++)
            BottomNavigationBarItem(
              label: _tabs[i].label,
              icon: Stack(
                clipBehavior: Clip.none,
                children: [
                  Icon(_tabs[i].icon),
                  if (i == 2 && criticalCount > 0)
                    Positioned(
                      top: -4,
                      right: -6,
                      child: Container(
                        padding: const EdgeInsets.all(2),
                        constraints: const BoxConstraints(
                          minWidth: 14,
                          minHeight: 14,
                        ),
                        decoration: const BoxDecoration(
                          color: AppTheme.neonRed,
                          shape: BoxShape.circle,
                        ),
                        child: Text(
                          '$criticalCount',
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                            fontFamily: 'RobotoMono',
                            fontSize: 8,
                            color: Colors.white,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

/// Thin neon gradient rule used under the app bar.
class NeonDividerBar extends StatelessWidget {
  const NeonDividerBar({super.key});

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 1,
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          colors: [Colors.transparent, AppTheme.neonGreen, Colors.transparent],
        ),
      ),
    );
  }
}
