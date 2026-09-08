import 'dart:async';

import 'package:flutter/material.dart';

import '../services/apk_scanner_service.dart';
import '../theme/app_theme.dart';
import 'home_screen.dart';
import 'scanning_screen.dart';

/// Branded splash. Also resolves whether the app was cold-started via
/// "Open with RAT3" before deciding where to navigate (fixes the old timer race).
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  static const _tailDelay = Duration(milliseconds: 400);
  static const _intentPollAttempts = 10;
  static const _intentPollInterval = Duration(milliseconds: 200);

  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 1500),
  )..forward();

  late final Animation<double> _fadeIn = CurvedAnimation(
    parent: _controller,
    curve: Curves.easeIn,
  );
  late final Animation<double> _scale = Tween<double>(
    begin: 0.7,
    end: 1,
  ).animate(CurvedAnimation(parent: _controller, curve: Curves.elasticOut));

  bool _incomingApk = false;

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    final apkPath = await _awaitInitialApk();
    if (mounted) setState(() => _incomingApk = apkPath != null);

    await Future<void>.delayed(_tailDelay);
    if (!mounted) return;

    await Navigator.of(context).pushReplacement(
      MaterialPageRoute<void>(
        builder: (_) => apkPath != null
            ? ScanningScreen(apkPath: apkPath)
            : const HomeScreen(),
      ),
    );
  }

  /// A `content://` APK is copied on a background thread, so poll a few times
  /// (~2 s total) before giving up and going to the home screen.
  Future<String?> _awaitInitialApk() async {
    final service = ApkScannerService();
    for (var attempt = 0; attempt < _intentPollAttempts; attempt++) {
      final path = await service.getInitialApkPath();
      if (path != null && path.isNotEmpty) return path;
      await Future<void>.delayed(_intentPollInterval);
    }
    return null;
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      body: Center(
        child: FadeTransition(
          opacity: _fadeIn,
          child: ScaleTransition(
            scale: _scale,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _shield(),
                const SizedBox(height: 32),
                const Text(
                  'RAT3',
                  style: TextStyle(
                    fontSize: 48,
                    fontWeight: FontWeight.bold,
                    color: AppColors.primary,
                    letterSpacing: 8,
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  'APK Security Scanner',
                  style: TextStyle(
                    fontSize: 14,
                    color: AppColors.textMuted,
                    letterSpacing: 2,
                  ),
                ),
                const SizedBox(height: 56),
                const SizedBox(
                  width: 180,
                  child: LinearProgressIndicator(
                    backgroundColor: AppColors.surface,
                    valueColor: AlwaysStoppedAnimation<Color>(
                      AppColors.primary,
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Text(
                  _incomingApk
                      ? 'APK detected — starting scan…'
                      : 'Initializing security modules…',
                  style: const TextStyle(
                    fontSize: 11,
                    color: AppColors.textMuted,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _shield() {
    return Container(
      width: 120,
      height: 120,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        border: Border.all(color: AppColors.primary, width: 2),
        boxShadow: [
          BoxShadow(
            color: AppColors.primary.withValues(alpha: 0.3),
            blurRadius: 30,
            spreadRadius: 5,
          ),
        ],
      ),
      child: const Icon(Icons.security, size: 60, color: AppColors.primary),
    );
  }
}
