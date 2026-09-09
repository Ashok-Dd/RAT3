import 'dart:developer' as developer;

import 'package:intl/intl.dart';

/// Logging utility — writes to debug console only, never to UI
class AppLogger {
  AppLogger._();

  static void info(String tag, String message) {
    developer.log('[INFO] $message', name: tag);
  }

  static void warning(String tag, String message) {
    developer.log('[WARN] $message', name: tag);
  }

  static void error(
    String tag,
    String message, [
    Object? error,
    StackTrace? stack,
  ]) {
    developer.log(
      '[ERROR] $message',
      name: tag,
      error: error,
      stackTrace: stack,
    );
  }
}

/// Formatting utilities
class AppFormatter {
  AppFormatter._();

  static String formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  static String formatDateTime(DateTime dt) {
    return DateFormat('yyyy-MM-dd HH:mm:ss').format(dt);
  }

  static String formatTimeAgo(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inSeconds < 60) return '${diff.inSeconds}s ago';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  static String formatDuration(int minutes) {
    if (minutes < 60) return '$minutes min';
    return '${(minutes / 60).toStringAsFixed(minutes % 60 == 0 ? 0 : 1)} hr';
  }
}
