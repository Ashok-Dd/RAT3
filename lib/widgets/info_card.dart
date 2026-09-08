import 'package:flutter/material.dart';

import '../theme/app_theme.dart';

/// The recurring "dark rounded panel with a coloured border" used across screens.
class InfoCard extends StatelessWidget {
  const InfoCard({
    super.key,
    required this.child,
    this.borderColor,
    this.padding = const EdgeInsets.all(16),
    this.glow = false,
  });

  final Widget child;
  final Color? borderColor;
  final EdgeInsets padding;
  final bool glow;

  @override
  Widget build(BuildContext context) {
    final border = borderColor ?? AppColors.border;
    return Container(
      width: double.infinity,
      padding: padding,
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: border),
        boxShadow: glow
            ? [
                BoxShadow(
                  color: border.withValues(alpha: 0.10),
                  blurRadius: 20,
                  spreadRadius: 2,
                ),
              ]
            : null,
      ),
      child: child,
    );
  }
}
