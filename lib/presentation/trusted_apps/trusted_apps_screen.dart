import 'package:flutter/material.dart';
import 'package:rat3/core/theme/app_theme.dart';
import 'package:rat3/data/services/platform_channel_service.dart';

/// TrustedAppsScreen
///
/// A single screen to manage which apps RAT3 should stop scanning. Each row is one
/// installed app with a toggle: ON means the user has explicitly vetted it themselves
/// (see AppTrustEngine's "Trusting an app yourself") — future scans skip it entirely
/// (no AppOps calls, no APK hashing, no Permission Tracker naming). OFF means it goes
/// through the full evidence ladder like any other app. A newly installed app is never
/// toggled on by default.
class TrustedAppsScreen extends StatefulWidget {
  const TrustedAppsScreen({super.key});

  @override
  State<TrustedAppsScreen> createState() => _TrustedAppsScreenState();
}

class _TrustedAppsScreenState extends State<TrustedAppsScreen> {
  final _platform = PlatformChannelService();

  bool _loading = true;
  String? _error;
  List<_AppRow> _apps = [];
  String _query = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final raw = await _platform.scanAllApps();
      final rows =
          raw.map((m) {
              return _AppRow(
                packageName: m['packageName'] as String? ?? '',
                appName: m['appName'] as String? ?? '',
                trusted: m['isUserTrusted'] as bool? ?? false,
              );
            }).toList()
            ..sort(
              (a, b) =>
                  a.appName.toLowerCase().compareTo(b.appName.toLowerCase()),
            );
      if (!mounted) return;
      setState(() {
        _apps = rows;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _toggle(int index, bool value) async {
    setState(() => _apps[index] = _apps[index].copyWith(trusted: value));
    await _platform.setUserTrusted(_apps[index].packageName, value);
  }

  List<_AppRow> get _filtered {
    if (_query.isEmpty) return _apps;
    final q = _query.toLowerCase();
    return _apps
        .where(
          (a) =>
              a.appName.toLowerCase().contains(q) ||
              a.packageName.toLowerCase().contains(q),
        )
        .toList();
  }

  @override
  Widget build(BuildContext context) {
    final trustedCount = _apps.where((a) => a.trusted).length;
    return Scaffold(
      backgroundColor: AppTheme.backgroundPrimary,
      appBar: AppBar(
        backgroundColor: AppTheme.backgroundPrimary,
        leading: IconButton(
          icon: const Icon(
            Icons.arrow_back_ios,
            color: AppTheme.neonGreen,
            size: 18,
          ),
          onPressed: () => Navigator.pop(context),
        ),
        title: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(
            color: AppTheme.neonCyan.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(4),
            border: Border.all(color: AppTheme.neonCyan.withValues(alpha: 0.4)),
          ),
          child: Text(
            'TRUSTED APPS',
            style: AppTheme.labelSmall.copyWith(
              color: AppTheme.neonCyan,
              letterSpacing: 2,
            ),
          ),
        ),
        actions: [
          if (_loading)
            const Padding(
              padding: EdgeInsets.only(right: 12),
              child: Center(
                child: SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    color: AppTheme.neonGreen,
                  ),
                ),
              ),
            )
          else
            IconButton(
              icon: const Icon(Icons.refresh, color: AppTheme.neonGreen),
              onPressed: _load,
            ),
        ],
      ),
      body: _error != null ? _buildError() : _buildBody(trustedCount),
    );
  }

  Widget _buildError() => Center(
    child: Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const Icon(Icons.error_outline, color: AppTheme.alertRed, size: 48),
        const SizedBox(height: 12),
        Text(
          _error ?? '',
          style: AppTheme.bodyMedium,
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 20),
        ElevatedButton(
          onPressed: _load,
          style: ElevatedButton.styleFrom(backgroundColor: AppTheme.neonGreen),
          child: Text(
            'RETRY',
            style: AppTheme.labelSmall.copyWith(
              color: AppTheme.backgroundPrimary,
            ),
          ),
        ),
      ],
    ),
  );

  Widget _buildBody(int trustedCount) {
    if (_loading && _apps.isEmpty) {
      return const Center(
        child: CircularProgressIndicator(color: AppTheme.neonGreen),
      );
    }
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Apps you mark trusted are skipped entirely in every future scan — '
                'no permission checks, no file hashing, no alerts naming them. '
                '$trustedCount of ${_apps.length} apps are currently trusted by you.',
                style: AppTheme.bodyMedium.copyWith(
                  color: AppTheme.textMuted,
                  fontSize: 11,
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                onChanged: (v) => setState(() => _query = v),
                style: AppTheme.bodyMedium,
                decoration: InputDecoration(
                  hintText: 'Search apps…',
                  hintStyle: AppTheme.bodyMedium.copyWith(
                    color: AppTheme.textMuted,
                  ),
                  prefixIcon: const Icon(
                    Icons.search,
                    color: AppTheme.textMuted,
                    size: 18,
                  ),
                  isDense: true,
                  filled: true,
                  fillColor: AppTheme.backgroundCard,
                  contentPadding: const EdgeInsets.symmetric(
                    vertical: 10,
                    horizontal: 12,
                  ),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(8),
                    borderSide: BorderSide(color: AppTheme.borderColor),
                  ),
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: _filtered.isEmpty
              ? Center(
                  child: Text(
                    'No apps match',
                    style: AppTheme.bodyMedium.copyWith(
                      color: AppTheme.textMuted,
                    ),
                  ),
                )
              : ListView.builder(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 100),
                  itemCount: _filtered.length,
                  itemBuilder: (_, i) {
                    final app = _filtered[i];
                    final realIndex = _apps.indexOf(app);
                    return _TrustRow(
                      app: app,
                      onChanged: (v) => _toggle(realIndex, v),
                    );
                  },
                ),
        ),
      ],
    );
  }
}

class _TrustRow extends StatelessWidget {
  final _AppRow app;
  final ValueChanged<bool> onChanged;
  const _TrustRow({required this.app, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final color = app.trusted ? AppTheme.neonGreen : AppTheme.textMuted;
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
      decoration: BoxDecoration(
        color: AppTheme.backgroundCard,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: color.withValues(alpha: app.trusted ? 0.4 : 0.15),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  app.appName,
                  style: AppTheme.bodyLarge.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
                Text(
                  app.packageName,
                  style: AppTheme.bodyMedium.copyWith(
                    color: AppTheme.textMuted,
                    fontSize: 10,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          Switch(
            value: app.trusted,
            activeThumbColor: AppTheme.neonGreen,
            onChanged: onChanged,
          ),
        ],
      ),
    );
  }
}

class _AppRow {
  final String packageName;
  final String appName;
  final bool trusted;
  const _AppRow({
    required this.packageName,
    required this.appName,
    required this.trusted,
  });

  _AppRow copyWith({bool? trusted}) => _AppRow(
    packageName: packageName,
    appName: appName,
    trusted: trusted ?? this.trusted,
  );
}
