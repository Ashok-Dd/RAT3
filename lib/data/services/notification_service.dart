import 'package:flutter/material.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/utils/app_utils.dart';
import 'package:rat3/data/models/app_models.dart';

/// Manages system-level push notifications for security alerts.
class NotificationService {
  static const String _tag = 'NotificationService';

  final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();

  bool _isInitialized = false;

  Future<void> init() async {
    try {
      const androidInit = AndroidInitializationSettings('@mipmap/ic_launcher');
      const initSettings = InitializationSettings(android: androidInit);

      await _plugin.initialize(
        initSettings,
        onDidReceiveNotificationResponse: _onNotificationTapped,
      );

      // Create the notification channel (Android 8+)
      const channel = AndroidNotificationChannel(
        AppConstants.notificationChannelId,
        AppConstants.notificationChannelName,
        description: 'Security alerts from RAT-Prevention',
        importance: Importance.high,
        enableLights: true,
        ledColor: Color(0xFF00FF88), // Flutter's Color, not a custom class
      );

      await _plugin
          .resolvePlatformSpecificImplementation<
              AndroidFlutterLocalNotificationsPlugin>()
          ?.createNotificationChannel(channel);

      _isInitialized = true;
      AppLogger.info(_tag, 'Notification service initialized');
    } catch (e, st) {
      AppLogger.error(_tag, 'Failed to init notifications', e, st);
    }
  }

  void _onNotificationTapped(NotificationResponse response) {
    AppLogger.info(_tag, 'Notification tapped: ${response.payload}');
  }

  /// Shows a notification for a security alert.
  Future<void> showAlertNotification(AlertEvent alert) async {
    if (!_isInitialized) return;

    try {
      final androidDetails = AndroidNotificationDetails(
        AppConstants.notificationChannelId,
        AppConstants.notificationChannelName,
        channelDescription: 'Security alerts from RAT-Prevention',
        importance: _importanceForSeverity(alert.severity),
        priority: _priorityForSeverity(alert.severity),
        color: const Color(0xFF00FF88), // Flutter Color — works correctly now
        icon: '@mipmap/ic_launcher',
        ticker: alert.title,
        styleInformation: BigTextStyleInformation(
          alert.userFriendlyMessage,
          summaryText: alert.severity.label,
        ),
      );

      final details = NotificationDetails(android: androidDetails);
      await _plugin.show(
        alert.id.hashCode,
        '🛡 ${alert.title}',
        alert.userFriendlyMessage,
        details,
        payload: alert.id,
      );
    } catch (e, st) {
      AppLogger.error(_tag, 'showAlertNotification failed', e, st);
    }
  }

  /// Shows a persistent low-priority monitoring status notification.
  Future<void> showMonitoringNotification(String statusText) async {
    if (!_isInitialized) return;

    try {
      const androidDetails = AndroidNotificationDetails(
        AppConstants.notificationChannelId,
        AppConstants.notificationChannelName,
        channelDescription: 'Active monitoring status',
        importance: Importance.low,
        priority: Priority.low,
        ongoing: true,
        autoCancel: false,
        icon: '@mipmap/ic_launcher',
      );

      const details = NotificationDetails(android: androidDetails);
      await _plugin.show(
        1, // Fixed ID so there's always only one monitoring notification
        '🛡 RAT-Prevention Active',
        statusText,
        details,
      );
    } catch (e, st) {
      AppLogger.error(_tag, 'showMonitoringNotification failed', e, st);
    }
  }

  Future<void> cancelAll() async {
    try {
      await _plugin.cancelAll();
    } catch (e) {
      AppLogger.error(_tag, 'cancelAll failed', e);
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  Importance _importanceForSeverity(AlertSeverity severity) {
    switch (severity) {
      case AlertSeverity.low:
        return Importance.low;
      case AlertSeverity.medium:
        return Importance.defaultImportance;
      case AlertSeverity.high:
        return Importance.high;
      case AlertSeverity.critical:
        return Importance.max;
    }
  }

  Priority _priorityForSeverity(AlertSeverity severity) {
    switch (severity) {
      case AlertSeverity.low:
        return Priority.low;
      case AlertSeverity.medium:
        return Priority.defaultPriority;
      case AlertSeverity.high:
        return Priority.high;
      case AlertSeverity.critical:
        return Priority.max;
    }
  }
}
