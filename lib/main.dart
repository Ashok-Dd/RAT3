import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import 'core/theme/app_theme.dart';
import 'data/services/app_controller.dart';
import 'presentation/app_shell.dart';
import 'presentation/onboarding/onboarding_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
      systemNavigationBarColor: AppTheme.backgroundSecondary,
      systemNavigationBarIconBrightness: Brightness.light,
    ),
  );

  final appController = AppController();
  await appController.init();

  runApp(
    ChangeNotifierProvider<AppController>.value(
      value: appController,
      child: const Rat3App(),
    ),
  );
}

class Rat3App extends StatelessWidget {
  const Rat3App({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'RAT3',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.darkTheme,
      home: const _RootGate(),
    );
  }
}

/// Shows onboarding until the user has been through the permission flow once,
/// then the main shell.
class _RootGate extends StatelessWidget {
  const _RootGate();

  @override
  Widget build(BuildContext context) {
    final onboarded = context.select<AppController, bool>(
      (c) => c.onboardingComplete,
    );
    return onboarded ? const AppShell() : const OnboardingScreen();
  }
}
