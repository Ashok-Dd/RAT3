import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../models/scan_result.dart';
import 'channels.dart';

/// Raised when the user must grant "install unknown apps" before an install can proceed.
class InstallPermissionRequiredException implements Exception {
  const InstallPermissionRequiredException(this.message);
  final String message;
  @override
  String toString() => message;
}

/// The only bridge between the Flutter UI and the Kotlin scanner.
///
/// This class is the **sole** owner of the `…/file` method-call handler; screens
/// listen through [onIncomingApk] instead of registering their own handlers.
class ApkScannerService {
  ApkScannerService._internal() {
    _fileChannel.setMethodCallHandler(_handleFileCall);
  }
  static final ApkScannerService _instance = ApkScannerService._internal();
  factory ApkScannerService() => _instance;

  static const _scannerChannel = MethodChannel(Channels.scanner);
  static const _fileChannel = MethodChannel(Channels.file);
  static const _installChannel = MethodChannel(Channels.install);
  static const _progressChannel = EventChannel(Channels.progress);

  /// Invoked when an APK arrives via "Open with RAT3" while the app is running.
  void Function(String apkPath)? onIncomingApk;

  Future<dynamic> _handleFileCall(MethodCall call) async {
    if (call.method == ScannerMethods.onIncomingApk) {
      final args = call.arguments;
      final path = args is Map ? args['apkPath'] as String? : null;
      if (path != null && path.isNotEmpty) onIncomingApk?.call(path);
    }
    return null;
  }

  /// APK path from the intent that cold-started the app, or null. May briefly
  /// return null while a `content://` APK is still being copied to cache.
  Future<String?> getInitialApkPath() async {
    try {
      return await _fileChannel.invokeMethod<String>(
        ScannerMethods.getInitialApkPath,
      );
    } on Exception catch (e) {
      debugPrint('[RAT3] getInitialApkPath: $e');
      return null;
    }
  }

  /// Opens the native file picker. Returns the resolved path, or null if cancelled.
  Future<String?> pickApkFile() async {
    try {
      return await _fileChannel.invokeMethod<String>(
        ScannerMethods.pickApkFile,
      );
    } on Exception catch (e) {
      debugPrint('[RAT3] pickApkFile: $e');
      return null;
    }
  }

  /// Runs the four-layer scan. [onLayerComplete] fires with the 0-based index of
  /// each finished layer. Throws [PlatformException] on scan failure.
  Future<ScanResult> scanApk({
    required String apkPath,
    required void Function(int layerIndex) onLayerComplete,
  }) async {
    final subscription = _progressChannel
        .receiveBroadcastStream(<String, String>{'apkPath': apkPath})
        .listen((event) {
          if (event is Map && event['layerComplete'] is int) {
            onLayerComplete(event['layerComplete'] as int);
          }
        });

    try {
      final raw = await _scannerChannel.invokeMethod<String>(
        ScannerMethods.scanApk,
        <String, String>{'apkPath': apkPath},
      );
      if (raw == null) {
        throw const FormatException('Scanner returned no result.');
      }
      return ScanResult.fromJson(json.decode(raw) as Map<String, dynamic>);
    } finally {
      await subscription.cancel();
    }
  }

  /// Hands the APK to the system installer. The system dialog is always shown.
  ///
  /// Throws [InstallPermissionRequiredException] if the user must first allow
  /// installing unknown apps, or [PlatformException] for other failures.
  Future<void> installApk(String apkPath) async {
    try {
      await _installChannel.invokeMethod<void>(
        ScannerMethods.installApk,
        <String, String>{'apkPath': apkPath},
      );
    } on PlatformException catch (e) {
      if (e.code == 'INSTALL_PERMISSION_REQUIRED') {
        throw InstallPermissionRequiredException(
          e.message ?? 'Allow RAT3 to install unknown apps, then try again.',
        );
      }
      rethrow;
    }
  }
}
