import 'dart:async';

import 'package:flutter/material.dart';

import '../services/apk_scanner_service.dart';
import '../theme/app_theme.dart';
import 'home_screen.dart';
import 'result_screen.dart';

enum _LayerState { waiting, scanning, complete }

class _Layer {
  _Layer({
    required this.name,
    required this.description,
    required this.icon,
    required this.color,
  });

  final String name;
  final String description;
  final IconData icon;
  final Color color;
  _LayerState state = _LayerState.waiting;
}

/// Shows per-layer progress while the native scan runs, then routes to the result.
class ScanningScreen extends StatefulWidget {
  const ScanningScreen({super.key, required this.apkPath});

  final String apkPath;

  @override
  State<ScanningScreen> createState() => _ScanningScreenState();
}

class _ScanningScreenState extends State<ScanningScreen> {
  static const _scanTimeout = Duration(seconds: 90);

  final _service = ApkScannerService();
  final _layers = [
    _Layer(
      name: 'App Safety Analysis',
      description: 'Manifest, permissions, SDK, accessibility…',
      icon: Icons.rule,
      color: AppColors.primary,
    ),
    _Layer(
      name: 'Permission Mismatch',
      description: 'Mapping permissions to API usage…',
      icon: Icons.compare_arrows,
      color: AppColors.accentYellow,
    ),
    _Layer(
      name: 'Malware Signatures',
      description: 'Signatures, blocklist, signing check…',
      icon: Icons.fingerprint,
      color: AppColors.accentOrange,
    ),
    _Layer(
      name: 'Heuristic Risk Model',
      description: 'Scoring the feature vector…',
      icon: Icons.psychology,
      color: AppColors.accentTeal,
    ),
  ];

  bool _complete = false;
  String? _error;
  String _status = 'Initializing scan…';

  @override
  void initState() {
    super.initState();
    _layers.first.state = _LayerState.scanning;
    _runScan();
  }

  Future<void> _runScan() async {
    setState(() {
      _error = null;
      _complete = false;
      _status = 'Initializing scan…';
      for (final l in _layers) {
        l.state = _LayerState.waiting;
      }
      _layers.first.state = _LayerState.scanning;
    });

    try {
      final result = await _service
          .scanApk(apkPath: widget.apkPath, onLayerComplete: _onLayerComplete)
          .timeout(_scanTimeout);

      if (!mounted) return;
      setState(() => _complete = true);
      await Future<void>.delayed(const Duration(milliseconds: 700));
      if (!mounted) return;
      await Navigator.of(context).pushReplacement(
        MaterialPageRoute<void>(builder: (_) => ResultScreen(result: result)),
      );
    } on TimeoutException {
      if (mounted) {
        setState(
          () => _error =
              'The scan timed out. The APK may be very large or damaged.',
        );
      }
    } catch (e) {
      if (mounted) setState(() => _error = _readableError(e));
    }
  }

  String _readableError(Object e) {
    final text = e.toString();
    if (text.contains('Not a valid APK')) {
      return 'That file is not a valid APK.';
    }
    if (text.contains('APK not found')) {
      return 'The APK file could not be found.';
    }
    return 'Scan failed: $text';
  }

  void _onLayerComplete(int index) {
    if (!mounted || index < 0 || index >= _layers.length) return;
    setState(() {
      _layers[index].state = _LayerState.complete;
      final next = index + 1;
      if (next < _layers.length) {
        _layers[next].state = _LayerState.scanning;
        _status = _layers[next].description;
      }
    });
  }

  void _goHome() {
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute<void>(builder: (_) => const HomeScreen()),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scanning APK'),
        automaticallyImplyLeading: false,
      ),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: _error != null ? _errorView() : _progressView(),
      ),
    );
  }

  Widget _progressView() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _fileChip(),
        const SizedBox(height: 32),
        const Text(
          'SECURITY ANALYSIS',
          style: TextStyle(
            color: AppColors.textMuted,
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 2,
          ),
        ),
        const SizedBox(height: 16),
        Expanded(
          child: ListView.separated(
            itemCount: _layers.length,
            separatorBuilder: (_, _) => const SizedBox(height: 16),
            itemBuilder: (_, i) => _layerCard(_layers[i], i),
          ),
        ),
        const SizedBox(height: 24),
        _statusBar(),
      ],
    );
  }

  Widget _errorView() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, size: 56, color: AppColors.danger),
          const SizedBox(height: 16),
          Text(
            _error!,
            textAlign: TextAlign.center,
            style: const TextStyle(
              color: AppColors.textSecondary,
              fontSize: 14,
            ),
          ),
          const SizedBox(height: 28),
          SizedBox(
            width: double.infinity,
            height: 50,
            child: ElevatedButton.icon(
              onPressed: _runScan,
              icon: const Icon(Icons.refresh),
              label: const Text('RETRY SCAN'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: AppColors.background,
              ),
            ),
          ),
          const SizedBox(height: 12),
          TextButton(
            onPressed: _goHome,
            child: const Text(
              'Back to Home',
              style: TextStyle(color: AppColors.textMuted),
            ),
          ),
        ],
      ),
    );
  }

  Widget _fileChip() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          const Icon(Icons.android, color: AppColors.accentTeal, size: 20),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              widget.apkPath.split('/').last,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _statusBar() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        children: [
          if (_complete)
            const Icon(
              Icons.check_circle,
              color: AppColors.accentTeal,
              size: 16,
            )
          else
            const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: AppColors.primary,
              ),
            ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              _complete ? 'Analysis complete!' : _status,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontSize: 13,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _layerCard(_Layer layer, int index) {
    final (borderColor, statusWidget) = switch (layer.state) {
      _LayerState.waiting => (
        AppColors.border,
        const Icon(
          Icons.radio_button_unchecked,
          color: AppColors.textMuted,
          size: 20,
        ),
      ),
      _LayerState.scanning => (
        layer.color,
        SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(strokeWidth: 2, color: layer.color),
        ),
      ),
      _LayerState.complete => (
        AppColors.accentTeal,
        const Icon(Icons.check_circle, color: AppColors.accentTeal, size: 20),
      ),
    };

    return AnimatedContainer(
      duration: const Duration(milliseconds: 300),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: borderColor),
      ),
      child: Row(
        children: [
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: layer.color.withValues(alpha: 0.1),
            ),
            child: Icon(layer.icon, color: layer.color, size: 22),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Layer ${index + 1}: ${layer.name}',
                  style: TextStyle(
                    color: layer.state == _LayerState.waiting
                        ? AppColors.textMuted
                        : AppColors.textPrimary,
                    fontWeight: FontWeight.w600,
                    fontSize: 14,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  layer.description,
                  style: const TextStyle(
                    color: AppColors.textMuted,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
          statusWidget,
        ],
      ),
    );
  }
}
