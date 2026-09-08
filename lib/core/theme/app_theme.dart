import 'package:flutter/material.dart';

/// RAT-Prevention Cybersecurity Theme
/// Dark background with neon green/cyan accents
class AppTheme {
  AppTheme._();

  // ── Color Palette ──────────────────────────────────────────────────────────
  static const Color backgroundPrimary = Color(0xFF050C12);
  static const Color backgroundSecondary = Color(0xFF0A1520);
  static const Color backgroundCard = Color(0xFF0D1B26);
  static const Color backgroundElevated = Color(0xFF112233);

  static const Color neonGreen = Color(0xFF00FF88);
  static const Color neonCyan = Color(0xFF00E5FF);
  static const Color neonBlue = Color(0xFF0088FF);
  static const Color neonRed = Color(0xFFFF3355);
  static const Color neonOrange = Color(0xFFFF8800);
  static const Color neonYellow = Color(0xFFFFDD00);

  // Aliases used in app scan screen
  static const Color alertRed    = neonRed;
  static const Color alertOrange = neonOrange;

  static const Color textPrimary = Color(0xFFE0F2F1);
  static const Color textSecondary = Color(0xFF80A0B0);
  static const Color textMuted = Color(0xFF405060);

  static const Color borderColor = Color(0xFF1A3040);
  static const Color borderAccent = Color(0xFF00FF8833);

  // ── Risk Colors ────────────────────────────────────────────────────────────
  static const Color colorSafe = neonGreen;
  static const Color colorSuspicious = neonOrange;
  static const Color colorDangerous = neonRed;

  /// Colour for a 0–100 risk score. Single source of truth for risk tinting.
  static Color riskColor(int score) {
    if (score <= 30) return colorSafe;
    if (score <= 60) return colorSuspicious;
    return colorDangerous;
  }

  // ── Spacing / radius tokens ───────────────────────────────────────────────
  static const double gap = 16;
  static const double radius = 8;
  static const EdgeInsets pagePadding = EdgeInsets.fromLTRB(16, 16, 16, 100);

  // ── Text Styles ────────────────────────────────────────────────────────────
  static const TextStyle displayLarge = TextStyle(
    fontFamily: 'Inter',
    fontSize: 48,
    fontWeight: FontWeight.w700,
    color: neonGreen,
    letterSpacing: 2.0,
  );

  static const TextStyle headlineLarge = TextStyle(
    fontFamily: 'Inter',
    fontSize: 24,
    fontWeight: FontWeight.w700,
    color: textPrimary,
    letterSpacing: 1.5,
  );

  static const TextStyle headlineMedium = TextStyle(
    fontFamily: 'Inter',
    fontSize: 18,
    fontWeight: FontWeight.w600,
    color: textPrimary,
    letterSpacing: 1.2,
  );

  static const TextStyle bodyLarge = TextStyle(
    fontFamily: 'Inter',
    fontSize: 14,
    fontWeight: FontWeight.w400,
    color: textPrimary,
    letterSpacing: 0.5,
  );

  static const TextStyle bodyMedium = TextStyle(
    fontFamily: 'Inter',
    fontSize: 12,
    fontWeight: FontWeight.w400,
    color: textSecondary,
    letterSpacing: 0.3,
  );

  static const TextStyle labelSmall = TextStyle(
    fontFamily: 'Inter',
    fontSize: 10,
    fontWeight: FontWeight.w500,
    color: textMuted,
    letterSpacing: 1.0,
  );

  // ── ThemeData ──────────────────────────────────────────────────────────────
  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: backgroundPrimary,
      colorScheme: const ColorScheme.dark(
        primary: neonGreen,
        secondary: neonCyan,
        surface: backgroundCard,
        error: neonRed,
        onPrimary: backgroundPrimary,
        onSecondary: backgroundPrimary,
        onSurface: textPrimary,
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: backgroundPrimary,
        foregroundColor: textPrimary,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          fontFamily: 'Inter',
          fontSize: 18,
          fontWeight: FontWeight.w700,
          color: neonGreen,
          letterSpacing: 2.0,
        ),
      ),
      cardTheme: CardThemeData(
        color: backgroundCard,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: const BorderSide(color: borderColor, width: 1),
        ),
        margin: const EdgeInsets.all(0),
      ),
      bottomNavigationBarTheme: const BottomNavigationBarThemeData(
        backgroundColor: backgroundSecondary,
        selectedItemColor: neonGreen,
        unselectedItemColor: textMuted,
        type: BottomNavigationBarType.fixed,
        elevation: 0,
        selectedLabelStyle: TextStyle(
          fontFamily: 'Inter',
          fontSize: 10,
          letterSpacing: 0.5,
        ),
        unselectedLabelStyle: TextStyle(
          fontFamily: 'Inter',
          fontSize: 10,
        ),
      ),
      dividerTheme: const DividerThemeData(
        color: borderColor,
        thickness: 1,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: neonGreen,
          foregroundColor: backgroundPrimary,
          textStyle: const TextStyle(
            fontFamily: 'Inter',
            fontWeight: FontWeight.w700,
            letterSpacing: 1.5,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(4),
          ),
        ),
      ),
      sliderTheme: const SliderThemeData(
        activeTrackColor: neonGreen,
        inactiveTrackColor: borderColor,
        thumbColor: neonGreen,
        overlayColor: Color(0x2200FF88),
        valueIndicatorColor: backgroundElevated,
        valueIndicatorTextStyle: TextStyle(
          fontFamily: 'Inter',
          color: neonGreen,
          fontWeight: FontWeight.w700,
        ),
      ),
      switchTheme: SwitchThemeData(
        thumbColor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.selected)
              ? neonGreen
              : textMuted,
        ),
        trackColor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.selected)
              ? const Color(0x4400FF88)
              : borderColor,
        ),
      ),
      snackBarTheme: const SnackBarThemeData(
        backgroundColor: backgroundElevated,
        contentTextStyle: TextStyle(
          fontFamily: 'Inter',
          color: textPrimary,
        ),
        shape: RoundedRectangleBorder(),
      ),
    );
  }
}

/// Extension for risk-level-specific colors.
extension RiskColorExtension on int {
  Color get riskColor => AppTheme.riskColor(this);
}