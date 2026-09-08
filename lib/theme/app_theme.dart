import 'package:flutter/material.dart';

/// Single source of truth for every colour in the app. Screens and widgets must
/// reference [AppColors] rather than hard-coding `Color(0xFF…)` literals.
abstract final class AppColors {
  // Surfaces
  static const background = Color(0xFF0D1117);
  static const surface = Color(0xFF161B22);
  static const border = Color(0xFF30363D);

  // Accents
  static const primary = Color(0xFF00E5FF);
  static const accentTeal = Color(0xFF1DE9B6);
  static const accentYellow = Color(0xFFFFD600);
  static const accentOrange = Color(0xFFFF6D00);

  // Verdict / risk
  static const safe = Color(0xFF1DE9B6);
  static const suspicious = Color(0xFFFFD600);
  static const danger = Color(0xFFFF4444);
  static const dangerText = Color(0xFFFF9999);

  // Text
  static const textPrimary = Color(0xFFFFFFFF);
  static const textSecondary = Color(0xFFCDD9E5);
  static const textMuted = Color(0xFF8B949E);

  /// Colour for a 0–100 risk score.
  static Color forScore(int score) => switch (score) {
    < 33 => safe,
    < 66 => suspicious,
    _ => danger,
  };
}

/// The app's dark theme.
ThemeData buildAppTheme() {
  return ThemeData(
    useMaterial3: true,
    fontFamily: 'Roboto',
    scaffoldBackgroundColor: AppColors.background,
    colorScheme: const ColorScheme.dark(
      primary: AppColors.primary,
      secondary: AppColors.accentTeal,
      surface: AppColors.surface,
      error: AppColors.danger,
    ),
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.surface,
      foregroundColor: AppColors.textPrimary,
    ),
  );
}
