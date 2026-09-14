import 'dart:math';
import 'package:flutter/material.dart';
import 'package:rat3/core/theme/app_theme.dart';

/// Renders a circular "water-filled ball" that visually represents the
/// current risk score (0–100). The water level rises with the score.
/// Includes a subtle wave animation for life.
class RiskBall extends StatefulWidget {
  final int score;
  final double size;

  const RiskBall({super.key, required this.score, this.size = 200});

  @override
  State<RiskBall> createState() => _RiskBallState();
}

class _RiskBallState extends State<RiskBall>
    with SingleTickerProviderStateMixin {
  late AnimationController _waveCtrl;

  @override
  void initState() {
    super.initState();
    _waveCtrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 3),
    )..repeat();
  }

  @override
  void dispose() {
    _waveCtrl.dispose();
    super.dispose();
  }

  Color get _waterColor {
    if (widget.score <= 30) return AppTheme.neonGreen;
    if (widget.score <= 60) return AppTheme.neonOrange;
    return AppTheme.neonRed;
  }

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: widget.size,
      height: widget.size,
      child: AnimatedBuilder(
        animation: _waveCtrl,
        builder: (_, _) {
          return CustomPaint(
            painter: _WaterBallPainter(
              score: widget.score,
              wavePhase: _waveCtrl.value * 2 * pi,
              waterColor: _waterColor,
            ),
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TweenAnimationBuilder<int>(
                    tween: IntTween(begin: 0, end: widget.score),
                    duration: const Duration(milliseconds: 800),
                    builder: (_, value, _) => Text(
                      '$value',
                      style: TextStyle(
                        fontFamily: 'Courier',
                        fontSize: widget.size * 0.28,
                        fontWeight: FontWeight.w700,
                        color: Colors.white,
                        shadows: [
                          Shadow(
                            color: _waterColor.withValues(alpha: 0.8),
                            blurRadius: 12,
                          ),
                        ],
                      ),
                    ),
                  ),
                  Text(
                    'RISK',
                    style: TextStyle(
                      fontFamily: 'Courier',
                      fontSize: widget.size * 0.07,
                      fontWeight: FontWeight.w500,
                      color: Colors.white60,
                      letterSpacing: 3,
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

class _WaterBallPainter extends CustomPainter {
  final int score;
  final double wavePhase;
  final Color waterColor;

  _WaterBallPainter({
    required this.score,
    required this.wavePhase,
    required this.waterColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2;

    // Clip everything to the circle shape
    final clipPath = Path()
      ..addOval(Rect.fromCircle(center: center, radius: radius));
    canvas.clipPath(clipPath);

    // Background of the ball
    canvas.drawOval(
      Rect.fromCircle(center: center, radius: radius),
      Paint()..color = AppTheme.backgroundElevated,
    );

    // Water fill level (fill from bottom)
    final fillFraction = score / 100.0;
    final waterTop = size.height * (1 - fillFraction);

    // Wave path
    final wavePath = Path();
    wavePath.moveTo(0, size.height);
    wavePath.lineTo(0, waterTop);

    for (double x = 0; x <= size.width; x++) {
      final y =
          waterTop +
          sin((x / size.width * 2 * pi) + wavePhase) * 6 +
          cos((x / size.width * pi) + wavePhase * 0.7) * 4;
      wavePath.lineTo(x, y);
    }

    wavePath.lineTo(size.width, size.height);
    wavePath.close();

    // Fill water
    canvas.drawPath(
      wavePath,
      Paint()
        ..color = waterColor.withValues(alpha: 0.5)
        ..style = PaintingStyle.fill,
    );

    // Second wave layer (offset phase for depth)
    final wave2Path = Path();
    wave2Path.moveTo(0, size.height);
    wave2Path.lineTo(0, waterTop + 5);

    for (double x = 0; x <= size.width; x++) {
      final y =
          waterTop +
          5 +
          sin((x / size.width * 2 * pi) + wavePhase + pi) * 4 +
          cos((x / size.width * pi) + wavePhase) * 3;
      wave2Path.lineTo(x, y);
    }

    wave2Path.lineTo(size.width, size.height);
    wave2Path.close();

    canvas.drawPath(
      wave2Path,
      Paint()
        ..color = waterColor.withValues(alpha: 0.3)
        ..style = PaintingStyle.fill,
    );

    // Outer ring
    canvas.drawOval(
      Rect.fromCircle(center: center, radius: radius - 1),
      Paint()
        ..color = waterColor.withValues(alpha: 0.6)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2,
    );

    // Inner glow ring
    canvas.drawOval(
      Rect.fromCircle(center: center, radius: radius - 4),
      Paint()
        ..color = waterColor.withValues(alpha: 0.15)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 6,
    );
  }

  @override
  bool shouldRepaint(_WaterBallPainter old) =>
      old.score != score ||
      old.wavePhase != wavePhase ||
      old.waterColor != waterColor;
}
