import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/data/services/app_controller.dart';
import 'package:rat3/presentation/alerts/alerts_screen.dart';
import 'package:rat3/presentation/dashboard/dashboard_screen.dart';
import 'package:rat3/presentation/network/network_screen.dart';
import 'package:rat3/presentation/scanner/scanner_screen.dart';
import 'package:rat3/presentation/settings/settings_screen.dart';

class AppShell extends StatefulWidget {
  const AppShell({super.key});

  @override
  State<AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<AppShell> {
  int _currentIndex = 0;

  static final List<({String label, IconData icon, Widget screen})> _tabs = [
    (
      label: 'Dashboard',
      icon: Icons.shield_outlined,
      screen: DashboardScreen()
    ),
     (label: 'Network', icon: Icons.wifi_outlined, screen: NetworkScreen()),
    (
      label: 'Alerts',
      icon: Icons.notifications_none_rounded,
      screen: AlertsScreen()
    ),
    (label: 'Scanner', icon: Icons.radar_outlined, screen: ScannerScreen()),
    (
      label: 'Settings',
      icon: Icons.settings_outlined,
      screen: SettingsScreen()
    ),
  ];

  @override
  Widget build(BuildContext context) {
    final ctrl = context.watch<AppController>();
    final criticalCount = ctrl.alertEngine.criticalCount;

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: AppTheme.neonGreen.withOpacity(0.1),
                borderRadius: BorderRadius.circular(3),
                border: Border.all(
                  color: AppTheme.neonGreen.withOpacity(0.4),
                ),
              ),
              child: Text(
                '🛡 RAT-PREVENTION',
                style: AppTheme.headlineLarge.copyWith(
                  fontSize: 14,
                  color: AppTheme.neonGreen,
                ),
              ),
            ),
          ],
        ),
        actions: [
          if (ctrl.isScanning)
            const Padding(
              padding: EdgeInsets.only(right: 8),
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
          const SizedBox(width: 8),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(
            height: 1,
            decoration: const BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  Colors.transparent,
                  AppTheme.neonGreen,
                  Colors.transparent,
                ],
              ),
            ),
          ),
        ),
      ),
      body: IndexedStack(
        index: _currentIndex,
        children: _tabs.map((t) => t.screen).toList(),
      ),
      bottomNavigationBar: Container(
        decoration: BoxDecoration(
          color: AppTheme.backgroundSecondary,
          border: const Border(
            top: BorderSide(color: AppTheme.borderColor, width: 1),
          ),
          boxShadow: [
            BoxShadow(
              color: AppTheme.neonGreen.withOpacity(0.05),
              blurRadius: 20,
              offset: const Offset(0, -5),
            ),
          ],
        ),
        child: BottomNavigationBar(
          currentIndex: _currentIndex,
          onTap: (i) => setState(() => _currentIndex = i),
          backgroundColor: Colors.transparent,
          elevation: 0,
          items: List.generate(_tabs.length, (i) {
            final tab = _tabs[i];
            final showBadge = i == 2 && criticalCount > 0; // Alerts tab

            return BottomNavigationBarItem(
              icon: Stack(
                clipBehavior: Clip.none,
                children: [
                  Icon(tab.icon),
                  if (showBadge)
                    Positioned(
                      top: -4,
                      right: -6,
                      child: Container(
                        padding: const EdgeInsets.all(2),
                        decoration: const BoxDecoration(
                          color: AppTheme.neonRed,
                          shape: BoxShape.circle,
                        ),
                        constraints: const BoxConstraints(
                          minWidth: 14,
                          minHeight: 14,
                        ),
                        child: Text(
                          '$criticalCount',
                          style: const TextStyle(
                            fontFamily: 'Courier',
                            fontSize: 8,
                            color: Colors.white,
                            fontWeight: FontWeight.w700,
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ),
                    ),
                ],
              ),
              label: tab.label,
            );
          }),
        ),
      ),
    );
  }
}
