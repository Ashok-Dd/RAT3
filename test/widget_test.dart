import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rat3/app.dart';
import 'package:rat3/services/channels.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    // No native side in a unit test — answer channel calls with "nothing".
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel(Channels.file),
          (call) async => null,
        );
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel(Channels.file), null);
  });

  testWidgets('app boots to the splash screen then the home screen', (
    tester,
  ) async {
    await tester.pumpWidget(const Rat3App());
    await tester.pump();

    expect(find.text('RAT3'), findsOneWidget);
    expect(find.text('APK Security Scanner'), findsOneWidget);

    // Splash polls for an incoming APK (~2 s) then navigates home.
    await tester.pump(const Duration(seconds: 3));
    await tester.pump();

    expect(find.text('Scan APK File'), findsOneWidget);
  });
}
