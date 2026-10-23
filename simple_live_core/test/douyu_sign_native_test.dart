import 'dart:io';

import 'package:simple_live_core/src/scripts/douyu_sign_native.dart';
import 'package:test/test.dart';

/// 用 2026-10-23 真实抓取的 homeH5Enc 脚本对拍：
/// quickjs 执行结果为
///   v=220120261023&did=10000000000000000000000000001501&tt=1792739428&sign=da4fcf8dd6c86a2142003dbbc31685d8
/// 纯 Dart 实现必须逐位一致。
void main() {
  late String script;

  setUpAll(() {
    script = File('test/fixtures/douyu_sign.js').readAsStringSync();
  });

  group('DouyuSignNative - 外壳还原', () {
    test('extractSignFnName 选中真身函数（避开诱饵）', () {
      // 脚本中同时存在诱饵函数 re7357c2c3 与真身 ub98484234
      expect(DouyuSignNative.extractSignFnName(script), 'ub98484234');
    });

    test('runShell 还原出内层签名函数源码', () {
      final inner = DouyuSignNative.runShell(script);
      expect(inner, isNotNull);
      expect(inner, isNotEmpty);
      // 内层源码应包含 MD5 入口与关键常量
      expect(inner, contains('re[I*2+1]=v1;'));
      expect(inner, contains('0123456789abcdef'));
    });
  });

  group('DouyuSignNative - 签名对拍', () {
    test('与 quickjs 基线一致', () {
      final sign = DouyuSignNative.getSign(
        script,
        '300358',
        '10000000000000000000000000001501',
        1792739428,
      );
      expect(
        sign,
        'v=220120261023&did=10000000000000000000000000001501&tt=1792739428&sign=da4fcf8dd6c86a2142003dbbc31685d8',
      );
    });

    test('不同 rid/did/tt 产出不同签名（参数确实参与计算）', () {
      final a = DouyuSignNative.getSign(
        script,
        '300358',
        '10000000000000000000000000001501',
        1792739428,
      );
      final b = DouyuSignNative.getSign(
        script,
        '999999',
        '10000000000000000000000000001501',
        1792739428,
      );
      final c = DouyuSignNative.getSign(
        script,
        '300358',
        '20000000000000000000000000001501',
        1792739428,
      );
      final d = DouyuSignNative.getSign(
        script,
        '300358',
        '10000000000000000000000000001501',
        1792739429,
      );
      expect(a, isNot(b));
      expect(a, isNot(c));
      expect(a, isNot(d));
      expect(b, isNot(c));
    });

    test('sign 段为 32 位小写 hex', () {
      final sign = DouyuSignNative.getSign(
        script,
        '300358',
        '10000000000000000000000000001501',
        1792739428,
      );
      final m = RegExp(r'sign=([0-9a-f]+)').firstMatch(sign!);
      expect(m, isNotNull);
      expect(m!.group(1)!.length, 32);
    });
  });

  group('DouyuSignNative - 异常输入', () {
    test('空脚本返回 null', () {
      expect(DouyuSignNative.getSign('', '300358', 'did', 1), isNull);
    });

    test('乱码脚本返回 null', () {
      expect(DouyuSignNative.getSign('function a(){}', '300358', 'did', 1),
          isNull);
    });
  });
}
