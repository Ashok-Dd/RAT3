import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'home_screen.dart';
import 'scanning_screen.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _fadeIn;
  late Animation<double> _scaleAnim;

  // If the app was opened via "Open with RAT3", this will be set
  String? _incomingApkPath;

  // Channel — same channel Kotlin uses to call onIncomingApk
  static const _fileChannel = MethodChannel('com.example.rat3/file');

  @override
  void initState() {
    super.initState();

    // Check if Kotlin already sent us an APK path before Flutter was ready.
    // This happens when the app is cold-started via "Open with RAT3".
    _checkForInitialIntent();

    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    );
    _fadeIn = CurvedAnimation(parent: _controller, curve: Curves.easeIn);
    _scaleAnim = Tween<double>(begin: 0.7, end: 1.0).animate(
      CurvedAnimation(parent: _controller, curve: Curves.elasticOut),
    );
    _controller.forward();

    // Short splash — then go to the right screen
    Timer(const Duration(milliseconds: 1800), _navigateNext);
  }

  /// Asks Kotlin if there was an APK intent before we registered our listener.
  /// This covers the cold-start case where the app launches for the first time.
  Future<void> _checkForInitialIntent() async {
    try {
      final result = await _fileChannel.invokeMethod<String?>('getInitialApkPath');
      if (result != null && result.isNotEmpty) {
        _incomingApkPath = result;
      }
    } catch (_) {
      // Channel may not implement this method — that's fine
    }
  }

  void _navigateNext() {
    if (!mounted) return;

    if (_incomingApkPath != null) {
      // Go directly to scan — skip HomeScreen entirely
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(
          builder: (_) => ScanningScreen(apkPath: _incomingApkPath!),
        ),
      );
    } else {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const HomeScreen()),
      );
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1117),
      body: Center(
        child: FadeTransition(
          opacity: _fadeIn,
          child: ScaleTransition(
            scale: _scaleAnim,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // Shield icon
                Container(
                  width: 120,
                  height: 120,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    border: Border.all(color: const Color(0xFF00E5FF), width: 2),
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFF00E5FF).withOpacity(0.3),
                        blurRadius: 30,
                        spreadRadius: 5,
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.security,
                    size: 60,
                    color: Color(0xFF00E5FF),
                  ),
                ),
                const SizedBox(height: 32),
                const Text(
                  'RAT3',
                  style: TextStyle(
                    fontSize: 48,
                    fontWeight: FontWeight.bold,
                    color: Color(0xFF00E5FF),
                    letterSpacing: 8,
                  ),
                ),
                const SizedBox(height: 8),
                const Text(
                  'APK Security Scanner',
                  style: TextStyle(
                    fontSize: 14,
                    color: Color(0xFF8B949E),
                    letterSpacing: 2,
                  ),
                ),
                const SizedBox(height: 64),
                SizedBox(
                  width: 180,
                  child: LinearProgressIndicator(
                    backgroundColor: const Color(0xFF161B22),
                    valueColor: const AlwaysStoppedAnimation<Color>(
                      Color(0xFF00E5FF),
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                Text(
                  _incomingApkPath != null
                      ? 'APK detected — starting scan...'
                      : 'Initializing security modules...',
                  style: const TextStyle(
                    fontSize: 11,
                    color: Color(0xFF8B949E),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}