import 'dart:async';

import 'package:flutter/material.dart';

import '../../core/theme/app_theme.dart';
import '../../widgets/common_widgets.dart';
import 'result_screen.dart';
import 'services/apk_scanner_service.dart';

enum _LayerState { waiting, scanning, complete }

class _Layer {
  _Layer({required this.name, required this.description, required this.icon});

  final String name;
  final String description;
  final IconData icon;
  _LayerState state = _LayerState.waiting;
}

/// Runs the 4-layer pre-install APK scan and shows per-layer progress.
class ApkScanningScreen extends StatefulWidget {
  const ApkScanningScreen({super.key, required this.apkPath});

  final String apkPath;

  @override
  State<ApkScanningScreen> createState() => _ApkScanningScreenState();
}

class _ApkScanningScreenState extends State<ApkScanningScreen> {
  static const _scanTimeout = Duration(seconds: 120);

  final _service = ApkScannerService();
  final _layers = [
    _Layer(
      name: 'App Safety Analysis',
      description: 'Manifest, permissions, SDK, accessibility…',
      icon: Icons.rule,
    ),
    _Layer(
      name: 'Permission Mismatch',
      description: 'Mapping permissions to API usage…',
      icon: Icons.compare_arrows,
    ),
    _Layer(
      name: 'Malware Signatures',
      description: 'Signatures, blocklist, signing check…',
      icon: Icons.fingerprint,
    ),
    _Layer(
      name: 'ML Malware Classifier',
      description: 'Running the 4-model ensemble…',
      icon: Icons.psychology,
    ),
  ];

  bool _complete = false;
  String? _error;
  String _status = 'Initializing scan…';

  @override
  void initState() {
    super.initState();
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
      await Future<void>.delayed(const Duration(milliseconds: 600));
      if (!mounted) return;
      await Navigator.of(context).pushReplacement(
        MaterialPageRoute<void>(
          builder: (_) => ApkResultScreen(result: result),
        ),
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('SCANNING APK'),
        automaticallyImplyLeading: _error != null,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: _error != null ? _errorView() : _progressView(),
        ),
      ),
    );
  }

  Widget _progressView() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        CyberCard(
          child: Row(
            children: [
              const Icon(Icons.android, color: AppTheme.neonCyan, size: 20),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  widget.apkPath.split('/').last,
                  style: AppTheme.bodyMedium,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        const SectionHeader(title: 'Security Analysis'),
        const SizedBox(height: 16),
        Expanded(
          child: ListView.separated(
            itemCount: _layers.length,
            separatorBuilder: (_, _) => const SizedBox(height: 12),
            itemBuilder: (_, i) => _layerCard(_layers[i], i),
          ),
        ),
        const SizedBox(height: 16),
        CyberCard(
          borderColor: AppTheme.neonGreen.withValues(alpha: 0.35),
          child: Row(
            children: [
              if (_complete)
                const Icon(
                  Icons.check_circle,
                  color: AppTheme.neonGreen,
                  size: 16,
                )
              else
                const SizedBox(
                  width: 16,
                  height: 16,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: AppTheme.neonGreen,
                  ),
                ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  _complete ? 'Analysis complete' : _status,
                  style: AppTheme.bodyMedium.copyWith(
                    color: AppTheme.textPrimary,
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _errorView() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, size: 56, color: AppTheme.neonRed),
          const SizedBox(height: 16),
          Text(_error!, textAlign: TextAlign.center, style: AppTheme.bodyLarge),
          const SizedBox(height: 28),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _runScan,
              icon: const Icon(Icons.refresh),
              label: const Text('RETRY SCAN'),
            ),
          ),
          const SizedBox(height: 12),
          TextButton(
            onPressed: () => Navigator.of(context).maybePop(),
            child: Text('Back', style: AppTheme.bodyMedium),
          ),
        ],
      ),
    );
  }

  Widget _layerCard(_Layer layer, int index) {
    final (border, statusWidget) = switch (layer.state) {
      _LayerState.waiting => (
        AppTheme.borderColor,
        const Icon(
          Icons.radio_button_unchecked,
          color: AppTheme.textMuted,
          size: 20,
        ),
      ),
      _LayerState.scanning => (
        AppTheme.neonGreen,
        const SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(
            strokeWidth: 2,
            color: AppTheme.neonGreen,
          ),
        ),
      ),
      _LayerState.complete => (
        AppTheme.neonGreen,
        const Icon(Icons.check_circle, color: AppTheme.neonGreen, size: 20),
      ),
    };

    return CyberCard(
      borderColor: border == AppTheme.borderColor ? null : border,
      child: Row(
        children: [
          Container(
            width: 38,
            height: 38,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: AppTheme.neonGreen.withValues(alpha: 0.1),
            ),
            child: Icon(layer.icon, color: AppTheme.neonGreen, size: 20),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Layer ${index + 1}: ${layer.name}',
                  style: AppTheme.bodyLarge.copyWith(
                    color: layer.state == _LayerState.waiting
                        ? AppTheme.textMuted
                        : AppTheme.textPrimary,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                const SizedBox(height: 2),
                Text(layer.description, style: AppTheme.labelSmall),
              ],
            ),
          ),
          statusWidget,
        ],
      ),
    );
  }
}
