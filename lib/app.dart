import 'package:flutter/material.dart';

import 'screens/scanning_screen.dart';
import 'screens/splash_screen.dart';
import 'services/apk_scanner_service.dart';
import 'theme/app_theme.dart';

/// Root widget. Wires the single [ApkScannerService.onIncomingApk] callback to
/// navigation so an "Open with RAT3" APK (cold or warm start) jumps straight to a scan.
class Rat3App extends StatefulWidget {
  const Rat3App({super.key});

  @override
  State<Rat3App> createState() => _Rat3AppState();
}

class _Rat3AppState extends State<Rat3App> {
  final _navigatorKey = GlobalKey<NavigatorState>();

  @override
  void initState() {
    super.initState();
    ApkScannerService().onIncomingApk = _openScan;
  }

  @override
  void dispose() {
    if (ApkScannerService().onIncomingApk == _openScan) {
      ApkScannerService().onIncomingApk = null;
    }
    super.dispose();
  }

  void _openScan(String apkPath) {
    _navigatorKey.currentState?.pushAndRemoveUntil(
      MaterialPageRoute<void>(builder: (_) => ScanningScreen(apkPath: apkPath)),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RAT3 — APK Security Scanner',
      debugShowCheckedModeBanner: false,
      navigatorKey: _navigatorKey,
      theme: buildAppTheme(),
      home: const SplashScreen(),
    );
  }
}
