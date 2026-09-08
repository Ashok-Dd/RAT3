/// Platform-channel names and method names, mirrored exactly in `MainActivity.kt`.
///
/// Keeping them in one file (instead of re-declaring `MethodChannel('…')` in
/// several widgets) is what prevents the old bug where three widgets each called
/// `setMethodCallHandler` on the same channel and silently overrode each other.
abstract final class Channels {
  static const scanner = 'com.example.rat3/scanner';
  static const file = 'com.example.rat3/file';
  static const install = 'com.example.rat3/install';
  static const progress = 'com.example.rat3/progress';
}

abstract final class ScannerMethods {
  static const scanApk = 'scanApk';
  static const pickApkFile = 'pickApkFile';
  static const getInitialApkPath = 'getInitialApkPath';
  static const onIncomingApk = 'onIncomingApk';
  static const installApk = 'installApk';
}
