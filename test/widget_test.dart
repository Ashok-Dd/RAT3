import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/widgets/common_widgets.dart';
import 'package:rat3/widgets/risk_ball.dart';

void main() {
  testWidgets('core shared widgets render under the app theme', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.darkTheme,
        home: const Scaffold(
          body: Column(
            children: [
              SectionHeader(title: 'Overview'),
              CyberCard(child: Text('hello')),
              RiskBall(score: 42, size: 120),
            ],
          ),
        ),
      ),
    );
    await tester.pump();

    expect(find.text('OVERVIEW'), findsOneWidget);
    expect(find.text('hello'), findsOneWidget);
    expect(find.byType(RiskBall), findsOneWidget);
  });

  test('AppTheme.riskColor bands', () {
    expect(AppTheme.riskColor(10), AppTheme.colorSafe);
    expect(AppTheme.riskColor(45), AppTheme.colorSuspicious);
    expect(AppTheme.riskColor(90), AppTheme.colorDangerous);
  });
}
