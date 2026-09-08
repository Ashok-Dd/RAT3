import 'package:flutter/material.dart';
import 'package:rat3/core/constants/app_constants.dart';
import 'package:rat3/core/theme/app_theme.dart';

// ── Cyber Card ─────────────────────────────────────────────────────────────

/// A themed card with neon border glow effect.
class CyberCard extends StatelessWidget {
  final Widget child;
  final Color? borderColor;
  final EdgeInsets? padding;
  final VoidCallback? onTap;

  const CyberCard({
    super.key,
    required this.child,
    this.borderColor,
    this.padding,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          color: AppTheme.backgroundCard,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: borderColor ?? AppTheme.borderColor,
            width: 1,
          ),
          boxShadow: borderColor != null
              ? [
                  BoxShadow(
                    color: borderColor!.withOpacity(0.15),
                    blurRadius: 12,
                    spreadRadius: 1,
                  ),
                ]
              : null,
        ),
        padding: padding ?? const EdgeInsets.all(16),
        child: child,
      ),
    );
  }
}

// ── Section Header ─────────────────────────────────────────────────────────

class SectionHeader extends StatelessWidget {
  final String title;
  final Widget? trailing;

  const SectionHeader({super.key, required this.title, this.trailing});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Container(
          width: 3,
          height: 16,
          color: AppTheme.neonGreen,
          margin: const EdgeInsets.only(right: 8),
        ),
        Text(
          title.toUpperCase(),
          style: AppTheme.labelSmall.copyWith(
            color: AppTheme.neonGreen,
            letterSpacing: 2,
            fontWeight: FontWeight.w700,
          ),
        ),
        const Spacer(),
        if (trailing != null) trailing!,
      ],
    );
  }
}

// ── Risk Level Badge ───────────────────────────────────────────────────────

class RiskLevelBadge extends StatelessWidget {
  final RiskLevel level;
  final bool large;

  const RiskLevelBadge({super.key, required this.level, this.large = false});

  Color get _color {
    switch (level) {
      case RiskLevel.safe:
        return AppTheme.colorSafe;
      case RiskLevel.suspicious:
        return AppTheme.colorSuspicious;
      case RiskLevel.dangerous:
        return AppTheme.colorDangerous;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: EdgeInsets.symmetric(
        horizontal: large ? 16 : 8,
        vertical: large ? 6 : 3,
      ),
      decoration: BoxDecoration(
        color: _color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(3),
        border: Border.all(color: _color.withOpacity(0.6), width: 1),
      ),
      child: Text(
        level.label,
        style: TextStyle(
          fontFamily: 'Courier',
          fontSize: large ? 14 : 10,
          fontWeight: FontWeight.w700,
          color: _color,
          letterSpacing: 1.5,
        ),
      ),
    );
  }
}

// ── Severity Badge ─────────────────────────────────────────────────────────

class SeverityBadge extends StatelessWidget {
  final AlertSeverity severity;

  const SeverityBadge({super.key, required this.severity});

  Color get _color {
    switch (severity) {
      case AlertSeverity.low:
        return AppTheme.neonCyan;
      case AlertSeverity.medium:
        return AppTheme.neonYellow;
      case AlertSeverity.high:
        return AppTheme.neonOrange;
      case AlertSeverity.critical:
        return AppTheme.neonRed;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: _color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(3),
        border: Border.all(color: _color, width: 1),
      ),
      child: Text(
        severity.label,
        style: TextStyle(
          fontFamily: 'Courier',
          fontSize: 9,
          fontWeight: FontWeight.w700,
          color: _color,
          letterSpacing: 1.5,
        ),
      ),
    );
  }
}

// ── Traffic Category Badge ─────────────────────────────────────────────────

class TrafficBadge extends StatelessWidget {
  final TrafficCategory category;

  const TrafficBadge({super.key, required this.category});

  Color get _color {
    switch (category) {
      case TrafficCategory.safe:
        return AppTheme.neonGreen;
      case TrafficCategory.suspicious:
        return AppTheme.neonOrange;
      case TrafficCategory.malicious:
        return AppTheme.neonRed;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: _color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(3),
        border: Border.all(color: _color.withOpacity(0.5)),
      ),
      child: Text(
        category.label,
        style: TextStyle(
          fontFamily: 'Courier',
          fontSize: 9,
          color: _color,
          fontWeight: FontWeight.w700,
          letterSpacing: 1,
        ),
      ),
    );
  }
}

// ── Neon Divider ────────────────────────────────────────────────────────────

class NeonDivider extends StatelessWidget {
  final Color color;

  const NeonDivider({super.key, this.color = AppTheme.borderColor});

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 1,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [Colors.transparent, color, Colors.transparent],
        ),
      ),
    );
  }
}

// ── Scanning Pulse Indicator ───────────────────────────────────────────────

class ScanPulse extends StatefulWidget {
  const ScanPulse({super.key});

  @override
  State<ScanPulse> createState() => _ScanPulseState();
}

class _ScanPulseState extends State<ScanPulse>
    with SingleTickerProviderStateMixin {
  late AnimationController _ctrl;
  late Animation<double> _anim;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 1),
    )..repeat(reverse: true);
    _anim = Tween<double>(begin: 0.3, end: 1.0).animate(_ctrl);
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _anim,
      builder: (_, __) => Container(
        width: 8,
        height: 8,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: AppTheme.neonGreen.withOpacity(_anim.value),
          boxShadow: [
            BoxShadow(
              color: AppTheme.neonGreen.withOpacity(_anim.value * 0.5),
              blurRadius: 6,
              spreadRadius: 1,
            ),
          ],
        ),
      ),
    );
  }
}
