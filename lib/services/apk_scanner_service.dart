import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import '../models/scan_result.dart';

/// ApkScannerService
///
/// Bridges the Flutter UI and the Kotlin native scanner layer
/// via Flutter Platform Channels.
///
/// Channel map (must match MainActivity.kt constants):
///   MethodChannel  com.example.rat3/scanner   → scanApk
///   MethodChannel  com.example.rat3/file      → pickApkFile, onIncomingApk
///   MethodChannel  com.example.rat3/install   → installApk
///   EventChannel   com.example.rat3/progress  → layer-by-layer progress
class ApkScannerService {
  // ─── Singleton ─────────────────────────────────────────────────────
  static final ApkScannerService _instance = ApkScannerService._internal();
  factory ApkScannerService() => _instance;

  ApkScannerService._internal() {
    _listenForIncomingApks();
  }

  // ─── Channels ──────────────────────────────────────────────────────
  static const _scannerCh  = MethodChannel('com.example.rat3/scanner');
  static const _fileCh     = MethodChannel('com.example.rat3/file');
  static const _installCh  = MethodChannel('com.example.rat3/install');
  static const _progressCh = EventChannel('com.example.rat3/progress');

  // ─── Incoming APK callback ─────────────────────────────────────────
  /// Set this to receive APK paths when the user opens an APK
  /// with "Open with RAT3" from their file manager.
  void Function(String apkPath)? onIncomingApk;

  void _listenForIncomingApks() {
    _fileCh.setMethodCallHandler((call) async {
      if (call.method == 'onIncomingApk') {
        final args = call.arguments;
        final path = args is Map ? args['apkPath'] as String? : null;
        if (path != null) onIncomingApk?.call(path);
      }
    });
  }

  // ─── File picker ───────────────────────────────────────────────────
  /// Opens a native file picker filtered to APK files.
  /// Returns the absolute path, or null if the user cancelled.
  Future<String?> pickApkFile() async {
    try {
      return await _fileCh.invokeMethod<String>('pickApkFile');
    } on PlatformException catch (e) {
      debugPrint('[RAT3] File picker error: ${e.message}');
      return null;
    }
  }

  // ─── Scanner ───────────────────────────────────────────────────────
  /// Runs the 4-layer APK scan via Kotlin native code.
  ///
  /// [apkPath]         – Absolute device path to the APK.
  /// [onLayerComplete] – Callback fired with layer index (0–3) as each
  ///                     layer finishes, for UI progress updates.
  ///
  /// Returns [ScanResult] on success. Throws [PlatformException] on failure.
  Future<ScanResult> scanApk({
    required String apkPath,
    required void Function(int layerIndex) onLayerComplete,
  }) async {
    // Listen to layer progress events from Kotlin EventChannel
    final sub = _progressCh
        .receiveBroadcastStream({'apkPath': apkPath})
        .listen((event) {
      if (event is Map && event.containsKey('layerComplete')) {
        onLayerComplete(event['layerComplete'] as int);
      }
    });

    try {
      final raw = await _scannerCh.invokeMethod<String>(
        'scanApk',
        {'apkPath': apkPath},
      );
      if (raw == null) throw Exception('Scanner returned no result.');
      return ScanResult.fromJson(json.decode(raw) as Map<String, dynamic>);
    } on PlatformException catch (e) {
      debugPrint('[RAT3] Scan error: ${e.message}');
      rethrow;
    } finally {
      await sub.cancel();
    }
  }

  // ─── Installer ─────────────────────────────────────────────────────
  /// Forwards the APK to the Android system PackageInstaller.
  /// The user always sees the system install dialog — RAT3 never
  /// installs silently.
  Future<void> installApk(String apkPath) async {
    try {
      await _installCh.invokeMethod<void>('installApk', {'apkPath': apkPath});
    } on PlatformException catch (e) {
      debugPrint('[RAT3] Install error: ${e.message}');
      rethrow;
    }
  }
}