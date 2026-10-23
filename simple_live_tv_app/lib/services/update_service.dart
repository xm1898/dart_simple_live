import 'package:dio/dio.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:url_launcher/url_launcher_string.dart';

/// GitHub Release 信息
class ReleaseInfo {
  final String version; // 1.14.2
  final String tagName; // v1.14.2
  final String url; // Release 页面
  final String notes; // 更新说明
  final String publishedAt;
  final bool prerelease;

  ReleaseInfo({
    required this.version,
    required this.tagName,
    required this.url,
    required this.notes,
    required this.publishedAt,
    required this.prerelease,
  });
}

class UpdateResult {
  final String currentVersion;
  final ReleaseInfo? latest; // null 表示检查失败

  UpdateResult({required this.currentVersion, this.latest});

  bool get hasUpdate =>
      latest != null && _compareVersion(latest!.version, currentVersion) > 0;
}

/// 应用内更新检查：查询本仓库 GitHub 最新 Release 并与当前版本比较
class UpdateService {
  static const owner = 'xm1898';
  static const repo = 'dart_simple_live';

  static int _compareVersion(String a, String b) {
    final pa = a.replaceFirst('v', '').split('.');
    final pb = b.replaceFirst('v', '').split('.');
    for (var i = 0; i < 3; i++) {
      final na = i < pa.length ? int.tryParse(pa[i]) ?? 0 : 0;
      final nb = i < pb.length ? int.tryParse(pb[i]) ?? 0 : 0;
      if (na != nb) return na.compareTo(nb);
    }
    return 0;
  }

  /// 检查更新；网络异常时 latest 为 null
  static Future<UpdateResult> check() async {
    final info = await PackageInfo.fromPlatform();
    final dio = Dio(
      BaseOptions(
        connectTimeout: const Duration(seconds: 10),
        receiveTimeout: const Duration(seconds: 10),
        headers: {
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'SimpleLive-UpdateCheck',
        },
      ),
    );
    final resp = await dio.get<Map<String, dynamic>>(
      'https://api.github.com/repos/$owner/$repo/releases/latest',
    );
    final data = resp.data;
    if (data == null) {
      return UpdateResult(currentVersion: info.version);
    }
    final release = ReleaseInfo(
      version: (data['tag_name'] as String? ?? '').replaceFirst('v', ''),
      tagName: data['tag_name'] as String? ?? '',
      url: data['html_url'] as String? ??
          'https://github.com/$owner/$repo/releases',
      notes: data['body'] as String? ?? '',
      publishedAt: data['published_at'] as String? ?? '',
      prerelease: data['prerelease'] as bool? ?? false,
    );
    return UpdateResult(currentVersion: info.version, latest: release);
  }

  /// 检查并弹窗展示，供设置页/我的页直接调用
  static Future<void> checkAndShow() async {
    SmartDialog.showLoading(msg: "正在检查更新...");
    UpdateResult result;
    try {
      result = await check();
    } catch (_) {
      SmartDialog.dismiss();
      SmartDialog.showToast("检查更新失败，请检查网络后重试");
      return;
    }
    SmartDialog.dismiss();

    if (result.latest == null) {
      SmartDialog.showToast("检查更新失败，请稍后重试");
      return;
    }
    if (!result.hasUpdate) {
      SmartDialog.showToast("当前已是最新版本 v${result.currentVersion}");
      return;
    }

    final latest = result.latest!;
    SmartDialog.show(
      builder: (context) => AlertDialog(
        title: Text("发现新版本 v${latest.version}"),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text("当前版本：v${result.currentVersion}"),
              const SizedBox(height: 4),
              Text(
                latest.publishedAt.isNotEmpty
                    ? "发布时间：${latest.publishedAt.substring(0, 10)}"
                    : "",
              ),
              const SizedBox(height: 8),
              Text(latest.notes.trim().isEmpty ? "（无更新说明）" : latest.notes),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: SmartDialog.dismiss,
            child: const Text("稍后再说"),
          ),
          TextButton(
            onPressed: () {
              SmartDialog.dismiss();
              launchUrlString(
                latest.url,
                mode: LaunchMode.externalApplication,
              );
            },
            child: const Text("前往下载"),
          ),
        ],
      ),
    );
  }
}
