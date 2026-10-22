import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_smart_dialog/flutter_smart_dialog.dart';
import 'package:get/get.dart';
import 'package:remixicon/remixicon.dart';
import 'package:simple_live_app/app/app_style.dart';
import 'package:simple_live_app/app/platform_utils.dart';
import 'package:simple_live_app/app/sites.dart';
import 'package:simple_live_app/modules/multi_room/multi_room_models.dart';
import 'package:simple_live_app/routes/app_navigation.dart';
import 'package:simple_live_app/services/desktop_multi_window_service.dart';
import 'package:simple_live_app/services/follow_service.dart';
import 'package:simple_live_app/widgets/net_image.dart';

/// 多开同屏选人页（仅桌面端）。
///
/// 上游把「进入多开」的入口放在关注页的多选模式里，而本项目的关注页已冻结为
/// 原版样式（没有多选态），因此这里单独提供一个桌面端入口：
/// 从「我的 → 多开同屏」进来，勾选 2 个及以上正在直播的关注，直接铺同屏网格。
class MultiRoomPickerPage extends StatefulWidget {
  const MultiRoomPickerPage({super.key});

  @override
  State<MultiRoomPickerPage> createState() => _MultiRoomPickerPageState();
}

class _MultiRoomPickerPageState extends State<MultiRoomPickerPage> {
  final Set<String> _selected = <String>{};
  bool _onlyLive = true;
  bool _starting = false;

  @override
  void initState() {
    super.initState();
    if (!PlatformUtils.supportsInlineMultiRoom) {
      return;
    }
    final service = FollowService.instance;
    // 先用本地缓存渲染，避免进页面空白；再按需拉一次状态。
    unawaited(service.loadData(updateStatus: false));
    if (service.followList.any((item) => item.liveStatus.value == 0)) {
      unawaited(service.startUpdateStatus());
    }
  }

  List<MultiRoomItem> _buildSelection() {
    final service = FollowService.instance;
    return service.followList
        .where((item) =>
            _selected.contains(item.id) &&
            item.liveStatus.value == 2 &&
            Sites.allSites.containsKey(item.siteId))
        .map(MultiRoomItem.fromFollow)
        .toList();
  }

  Future<void> _start() async {
    if (_starting) {
      return;
    }
    final rooms = _buildSelection();
    if (rooms.length < 2) {
      SmartDialog.showToast("至少选择 2 个直播中的关注");
      return;
    }
    setState(() => _starting = true);
    try {
      if (await DesktopMultiWindowService.openRooms(rooms)) {
        Get.back();
        return;
      }
      AppNavigator.toMultiRoom(rooms);
    } finally {
      if (mounted) {
        setState(() => _starting = false);
      }
    }
  }

  String _statusText(int status) {
    switch (status) {
      case 2:
        return "直播中";
      case 1:
        return "未开播";
      default:
        return "加载中";
    }
  }

  Color _statusColor(BuildContext context, int status) {
    switch (status) {
      case 2:
        return Theme.of(context).colorScheme.primary;
      case 1:
        return Colors.grey;
      default:
        return Colors.orange;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!PlatformUtils.supportsInlineMultiRoom) {
      return Scaffold(
        appBar: AppBar(title: const Text("多开同屏")),
        body: const Center(child: Text("多开同屏仅支持桌面端")),
      );
    }
    return Scaffold(
      appBar: AppBar(
        title: const Text("多开同屏"),
        actions: [
          IconButton(
            tooltip: "刷新直播状态",
            onPressed: () => FollowService.instance.startUpdateStatus(
              force: true,
            ),
            icon: const Icon(Remix.refresh_line),
          ),
          IconButton(
            tooltip: _onlyLive ? "显示全部关注" : "只看直播中",
            onPressed: () => setState(() => _onlyLive = !_onlyLive),
            icon: Icon(_onlyLive ? Icons.filter_alt : Icons.filter_alt_off),
          ),
        ],
      ),
      body: Obx(() {
        final service = FollowService.instance;
        final all = service.followList
            .where((item) => Sites.allSites.containsKey(item.siteId))
            .toList();
        final list = _onlyLive
            ? all.where((item) => item.liveStatus.value == 2).toList()
            : all;
        if (list.isEmpty) {
          return Center(
            child: Padding(
              padding: AppStyle.edgeInsetsA24,
              child: Text(
                all.isEmpty
                    ? "还没有关注任何主播"
                    : (_onlyLive ? "当前没有正在直播的关注\n可点右上角筛选图标查看全部" : "暂无可多开的关注"),
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.grey),
              ),
            ),
          );
        }
        return ListView.separated(
          padding: AppStyle.pagePadding(),
          itemCount: list.length,
          separatorBuilder: (_, __) => AppStyle.divider,
          itemBuilder: (context, index) {
            final item = list[index];
            final status = item.liveStatus.value;
            final checked = _selected.contains(item.id);
            final enabled = status == 2;
            return ListTile(
              leading: NetImage(
                item.face,
                width: 44,
                height: 44,
                borderRadius: 22,
              ),
              title: Text(
                item.userName,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
              subtitle: Row(
                children: [
                  Text(
                    Sites.allSites[item.siteId]?.name ?? item.siteId,
                    style: const TextStyle(fontSize: 12),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    _statusText(status),
                    style: TextStyle(
                      fontSize: 12,
                      color: _statusColor(context, status),
                    ),
                  ),
                ],
              ),
              trailing: Checkbox(
                value: checked,
                onChanged: enabled
                    ? (value) {
                        setState(() {
                          if (value == true) {
                            _selected.add(item.id);
                          } else {
                            _selected.remove(item.id);
                          }
                        });
                      }
                    : null,
              ),
              enabled: enabled,
              onTap: enabled
                  ? () {
                      setState(() {
                        if (checked) {
                          _selected.remove(item.id);
                        } else {
                          _selected.add(item.id);
                        }
                      });
                    }
                  : null,
            );
          },
        );
      }),
      bottomNavigationBar: SafeArea(
        child: Padding(
          padding: AppStyle.edgeInsetsA12,
          child: Row(
            children: [
              Expanded(
                child: Text(
                  _selected.isEmpty
                      ? "勾选 2 个及以上直播中的关注"
                      : "已选 ${_selected.length} 个",
                  style: const TextStyle(color: Colors.grey),
                ),
              ),
              FilledButton.icon(
                onPressed: _starting ? null : _start,
                icon: const Icon(Remix.layout_grid_line, size: 18),
                label: Text(_starting ? "正在打开…" : "开始同屏"),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
