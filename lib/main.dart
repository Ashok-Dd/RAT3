import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'screens/splash_screen.dart';
import 'screens/scanning_screen.dart';
import 'services/apk_scanner_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const RAT3App());
}

class RAT3App extends StatefulWidget {
  const RAT3App({super.key});

  @override
  State<RAT3App> createState() => _RAT3AppState();
}

class _RAT3AppState extends State<RAT3App> {
  // Navigator key so we can push routes from outside the widget tree
  final _navKey = GlobalKey<NavigatorState>();

  // Channel to receive "Open with RAT3" intents from Kotlin
  static const _fileChannel = MethodChannel('com.example.rat3/file');

  @override
  void initState() {
    super.initState();

    // Listen for APK intents forwarded from MainActivity.kt
    // This fires when the user picks "Open with RAT3" in their file manager
    _fileChannel.setMethodCallHandler((call) async {
      if (call.method == 'onIncomingApk') {
        final args = call.arguments;
        final apkPath = args is Map ? args['apkPath'] as String? : null;
        if (apkPath != null && apkPath.isNotEmpty) {
          _navigateToScan(apkPath);
        }
      }
    });
  }

  /// Pushes directly to ScanningScreen, clearing the entire back stack.
  /// Works whether we're on SplashScreen, HomeScreen, or anywhere else.
  void _navigateToScan(String apkPath) {
    _navKey.currentState?.pushAndRemoveUntil(
      MaterialPageRoute(
        builder: (_) => ScanningScreen(apkPath: apkPath),
      ),
      (route) => false, // remove all previous routes
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RAT3 - APK Security Scanner',
      debugShowCheckedModeBanner: false,
      navigatorKey: _navKey,
      theme: ThemeData(
        colorScheme: const ColorScheme.dark(
          primary: Color(0xFF00E5FF),
          secondary: Color(0xFF1DE9B6),
          surface: Color(0xFF0D1117),
          error: Color(0xFFFF4444),
        ),
        scaffoldBackgroundColor: const Color(0xFF0D1117),
        fontFamily: 'Roboto',
        useMaterial3: true,
      ),
      home: const SplashScreen(),
    );
  }
}