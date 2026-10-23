import 'dart:convert';

import 'package:crypto/crypto.dart';

/// 斗鱼播放签名纯 Dart 实现，不依赖 JS 引擎（dart_quickjs / native assets）。
///
/// 背景：dart_quickjs 通过 Dart Hooks(native assets) 在构建期编译 C 代码，
/// Windows 桌面包经常打不进 dart_quickjs.dll，导致斗鱼签名刷新失败。
/// 本类按 homeH5Enc 返回的脚本动态解析并执行：
///   1. 外壳函数（位运算序列）还原出内层签名函数源码；
///   2. 从内层源码提取 date 与 k2，用 Dart 复算 MD5+TEA+位运算+hex 输出。
/// 与 quickjs 执行结果逐位一致（已用同一脚本对拍验证）。
class DouyuSignNative {
  static const int _m32 = 0xFFFFFFFF;

  /// 外壳函数特征：function name(a,b,c){var rk=[...]
  static final RegExp _shellFnRe = RegExp(
    r'function\s+(\w+)\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)\s*\{\s*var\s+rk\s*=\s*\[([^\]]*)\]',
  );

  /// 从脚本中选出真正的外壳签名函数名。
  /// 脚本里存在多个同形态函数（诱饵），真身判据：函数体内 `var strc`
  /// 之前含有 `String.fromCharCode`（字节数组还原标志）。
  /// 找不到时返回 null。
  static String? extractSignFnName(String script) {
    final cands = _shellFnRe.allMatches(script).toList();
    if (cands.isEmpty) return null;
    for (final c in cands) {
      final seg = script.substring(c.start);
      final si = seg.indexOf('var strc');
      if (si > 0 && seg.substring(0, si).contains('String.fromCharCode')) {
        return c.group(1);
      }
    }
    return cands.last.group(1);
  }

  static int _rotl(int x, int n) {
    n %= 32;
    if (n == 0) return x & _m32;
    return ((x << n) | (x >> (32 - n))) & _m32;
  }

  static int _rotr(int x, int n) {
    n %= 32;
    if (n == 0) return x & _m32;
    return ((x >> n) | (x << (32 - n))) & _m32;
  }

  static List<int> _parseIntList(String s) {
    final re = RegExp(r'0x[0-9a-fA-F]+|\d+');
    final out = <int>[];
    for (final m in re.allMatches(s)) {
      final t = m.group(0)!;
      out.add(t.startsWith('0x')
          ? int.parse(t.substring(2), radix: 16)
          : int.parse(t));
    }
    return out;
  }

  static String _bytesToStr(List<int> v) {
    final out = <int>[];
    for (final x in v) {
      out.add(x & 0xff);
      out.add((x >> 8) & 0xff);
      out.add((x >> 16) & 0xff);
      out.add((x >> 24) & 0xff);
    }
    // 还原出的内层函数源码是 latin1/ascii 文本
    return latin1.decode(out);
  }

  /// 执行外壳函数，还原内层签名函数源码。
  /// 失败时返回 null（调用方应回退到 quickjs 或旧参数）。
  static String? runShell(String script) {
    try {
      final cands = _shellFnRe.allMatches(script).toList();
      if (cands.isEmpty) return null;
      Match? best;
      for (final c in cands) {
        final seg = script.substring(c.start);
        final si = seg.indexOf('var strc');
        if (si > 0 && seg.substring(0, si).contains('String.fromCharCode')) {
          best = c;
          break;
        }
      }
      best ??= cands.last;
      final m = best;
      final rk = _parseIntList(m.group(5)!);

      // 字节数组：签名函数 return 之后的第一个大数组
      final retPos = script.indexOf('return', m.end);
      final arrRe = RegExp(r'var\s+(\w+)\s*=\s*\[([^\]]*)\]\s*;');
      List<int>? arrVals;
      for (final m2 in arrRe.allMatches(
        script.substring(retPos > 0 ? retPos : m.end),
      )) {
        final vals = _parseIntList(m2.group(2)!);
        if (vals.length > 100) {
          arrVals = vals;
          break;
        }
      }
      if (arrVals == null) return null;
      final v = arrVals.map((x) => x & _m32).toList();

      final body = script.substring(m.start);
      final lkM = RegExp(r'var\s+lk\s*=\s*\[([^\]]*)\]').firstMatch(body);
      final kM = RegExp(r'var\s+k\s*=\s*\[([^\]]*)\]').firstMatch(body);
      final k2M = RegExp(r'var\s+k2\s*=\s*\[([^\]]*)\]').firstMatch(body);
      final lk = lkM != null ? _parseIntList(lkM.group(1)!) : <int>[0, 0];
      final k = kM != null ? _parseIntList(kM.group(1)!) : <int>[0, 0, 0, 0];
      final k2 = k2M != null ? _parseIntList(k2M.group(1)!) : <int>[0, 0];

      final strcPos = body.indexOf('var strc');
      if (strcPos < 0) return null;
      final fnbody = body.substring(0, strcPos);

      // 事件（位置, 执行函数）按出现顺序执行
      final events = <List<dynamic>>[];

      // 1) 初始 xor 循环
      for (final sm in RegExp(
        r'for\s*\(\s*var\s+\w+\s*=\s*(\d+)\s*;\s*\w+\s*<\s*(\d+)\s*;\s*\w+\s*\+\+\s*\)\s*\{\s*\w+\s*\[\s*\w+\s*\]\s*\^=\s*(0x[0-9a-fA-F]+|\d+)\s*;\s*\}',
      ).allMatches(fnbody)) {
        final lo = int.parse(sm.group(1)!);
        final hi = int.parse(sm.group(2)!);
        final t = sm.group(3)!;
        final c = t.startsWith('0x')
            ? int.parse(t.substring(2), radix: 16)
            : int.parse(t);
        events.add([
          sm.start,
          () {
            for (var i = lo; i < hi && i < v.length; i++) {
              v[i] = v[i] ^ c;
            }
          },
        ]);
      }

      // 2) 简单语句 v[N] <op> lk[i]
      void addSimple(RegExp pat, void Function(int, int) fn) {
        for (final sm in pat.allMatches(fnbody)) {
          final idx = int.parse(sm.group(1)!);
          final li = int.parse(sm.group(2)!);
          events.add([sm.start, () => fn(idx, li)]);
        }
      }

      addSimple(
        RegExp(
          r'\w+\s*\[\s*(\d+)\s*\]\s*=\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*>>>\s*\(\s*lk\s*\[\s*(\d+)\s*\]\s*%\s*16\s*\)\s*\)\s*\|\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*<<\s*\(\s*\d+\s*-\s*\(\s*lk\s*\[\s*\d+\s*\]\s*%\s*16\s*\)\s*\)\s*\)',
        ),
        (idx, li) => v[idx] = _rotr(v[idx], lk[li] % 16),
      );
      addSimple(
        RegExp(
          r'\w+\s*\[\s*(\d+)\s*\]\s*=\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*<<\s*\(\s*lk\s*\[\s*(\d+)\s*\]\s*%\s*16\s*\)\s*\)\s*\|\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*>>>\s*\(\s*\d+\s*-\s*\(\s*lk\s*\[\s*\d+\s*\]\s*%\s*16\s*\)\s*\)\s*\)',
        ),
        (idx, li) => v[idx] = _rotl(v[idx], lk[li] % 16),
      );
      addSimple(
        RegExp(r'\w+\s*\[\s*(\d+)\s*\]\s*\+=\s*lk\s*\[\s*(\d+)\s*\]'),
        (idx, li) => v[idx] = (v[idx] + lk[li]) & _m32,
      );
      addSimple(
        RegExp(r'\w+\s*\[\s*(\d+)\s*\]\s*-=\s*lk\s*\[\s*(\d+)\s*\]'),
        (idx, li) => v[idx] = (v[idx] - lk[li]) & _m32,
      );
      addSimple(
        RegExp(r'\w+\s*\[\s*(\d+)\s*\]\s*\^=\s*lk\s*\[\s*(\d+)\s*\]'),
        (idx, li) => v[idx] = v[idx] ^ lk[li],
      );

      // 3) TEA 式循环
      final mtea = RegExp(
        r'for\s*\(\s*var\s+(\w+)\s*=\s*(\d+)\s*;\s*\1\s*<\s*(\d+)\s*;\s*\1\s*\+=\s*(\d+)\s*\)\s*\{'
        r'[^{}]*?var\s+\w+\s*,\s*(\w+)\s*=\s*\w+\s*\[\s*[^\]]+?\s*\]\s*\^\s*(\w+)\s*\[\s*(\d+)\s*\]\s*,\s*'
        r'(\w+)\s*=\s*\w+\s*\[\s*[^\]]+?\s*\]\s*\^\s*(\w+)\s*\[\s*(\d+)\s*\]\s*,\s*'
        r'(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(\w+)\s*=\s*\w+\s*\*\s*rk\s*\[\s*\w+\s*/\s*(\d+)\s*\]\s*;',
      ).firstMatch(fnbody);
      if (mtea != null) {
        final step = int.parse(mtea.group(4)!);
        final kidx0 = int.parse(mtea.group(7)!);
        final kidx1 = int.parse(mtea.group(10)!);
        final dRaw = mtea.group(12)!;
        final d = dRaw.startsWith('0x')
            ? int.parse(dRaw.substring(2), radix: 16)
            : int.parse(dRaw);
        events.add([
          mtea.start,
          () {
            for (var i = 0; i < v.length - 1; i += step) {
              var v0 = v[i] ^ k2[kidx0];
              var v1 = v[i + 1] ^ k2[kidx1];
              final rounds = i ~/ step < rk.length ? rk[i ~/ step] : 32;
              var s = (d * rounds) & _m32;
              for (var r = 0; r < rounds; r++) {
                final fa = (((((v0 << 4) & _m32) ^ (v0 >> 5)) + v0) & _m32);
                final fb = (s + k[(s >> 11) & 3]) & _m32;
                v1 = (v1 - (fa ^ fb)) & _m32;
                s = (s - d) & _m32;
                final fa2 = (((((v1 << 4) & _m32) ^ (v1 >> 5)) + v1) & _m32);
                final fb2 = (s + k[s & 3]) & _m32;
                v0 = (v0 - (fa2 ^ fb2)) & _m32;
              }
              v[i] = v0 ^ k2[kidx1];
              v[i + 1] = v1 ^ k2[kidx0];
            }
          },
        ]);
      }

      // 4) 尾部反向 xor 链
      for (final sm in RegExp(
        r'for\s*\(\s*var\s+\w+\s*=\s*(\d+)\s*;\s*\w+\s*>\s*(\d+)\s*;\s*\w+\s*--\s*\)\s*\{\s*\w+\s*\[\s*\w+\s*\]\s*\^=\s*\w+\s*\[\s*\w+\s*-\s*1\s*\]\s*;\s*\}',
      ).allMatches(fnbody)) {
        final hi = int.parse(sm.group(1)!);
        events.add([
          sm.start,
          () {
            for (var i = hi; i > 0; i--) {
              if (i < v.length) v[i] = v[i] ^ v[i - 1];
            }
          },
        ]);
      }

      // 5) v[0]^=C（TEA 之后）
      final base = fnbody.lastIndexOf('}for');
      final mv0 = RegExp(r'\w+\s*\[\s*0\s*\]\s*\^=\s*(0x[0-9a-fA-F]+|\d+)')
          .firstMatch(fnbody.substring(base > 0 ? base : 0));
      if (mv0 != null) {
        final t = mv0.group(1)!;
        final c0 = t.startsWith('0x')
            ? int.parse(t.substring(2), radix: 16)
            : int.parse(t);
        events.add([(base > 0 ? base : 0) + mv0.start, () => v[0] = v[0] ^ c0]);
      }

      events.sort((a, b) => (a[0] as int).compareTo(b[0] as int));
      for (final e in events) {
        (e[1] as void Function())();
      }
      return _bytesToStr(v);
    } catch (_) {
      return null;
    }
  }

  /// 内层签名算法：MD5 + LE 组装 + TEA + 位运算序列 + nibble-swap hex。
  static String? signInner(String inner, String rid, String did, int tt) {
    try {
      final dm = RegExp(r'"(\d{10,12})"').firstMatch(inner);
      if (dm == null) return null;
      final date = dm.group(1)!;
      final k2m = RegExp(r'var\s+k2\s*=\s*\[([^\]]*)\]').firstMatch(inner);
      if (k2m == null) return null;
      final k2 = _parseIntList(k2m.group(1)!);
      if (k2.length < 4) return null;

      final cb = rid + did + tt.toString() + date;
      final rb = md5.convert(utf8.encode(cb)).toString();
      final re = <int>[];
      for (var i = 0; i < 4; i++) {
        final hex8 = rb.substring(i * 8, i * 8 + 8);
        var val = 0;
        for (var b = 0; b < 4; b++) {
          val |= int.parse(hex8.substring(b * 2, b * 2 + 2), radix: 16) << (b * 8);
        }
        re.add(val & _m32);
      }

      // 标准 TEA（加法）
      for (var big = 0; big < 2; big++) {
        var v0 = re[big * 2];
        var v1 = re[big * 2 + 1];
        var s = 0;
        const delta = 0x9e3779b9;
        for (var i = 0; i < 32; i++) {
          s = (s + delta) & _m32;
          final fa = ((((v1 << 4) & _m32) + k2[0]) & _m32) ^
              ((v1 + s) & _m32) ^
              (((v1 >> 5) + k2[1]) & _m32);
          v0 = (v0 + fa) & _m32;
          final fb = ((((v0 << 4) & _m32) + k2[2]) & _m32) ^
              ((v0 + s) & _m32) ^
              (((v0 >> 5) + k2[3]) & _m32);
          v1 = (v1 + fb) & _m32;
        }
        re[big * 2] = v0;
        re[big * 2 + 1] = v1;
      }

      // 位运算序列（TEA 之后到 hex 输出之前）
      final seqStart = inner.indexOf('re[I*2+1]=v1;');
      final seqEnd = inner.indexOf('{var hc=');
      if (seqStart < 0 || seqEnd < 0 || seqEnd <= seqStart) return null;
      final seq = inner.substring(seqStart, seqEnd);
      final evs = <List<dynamic>>[];

      void addSeq(RegExp pat, void Function(int, int) fn) {
        for (final sm in pat.allMatches(seq)) {
          final idx = int.parse(sm.group(1)!);
          final ki = int.parse(sm.group(2)!);
          evs.add([sm.start, () => fn(idx, ki)]);
        }
      }

      addSeq(
        RegExp(
          r'\w+\s*\[\s*(\d+)\s*\]\s*=\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*<<\s*\(\s*k2\s*\[\s*(\d+)\s*\]\s*%\s*16\s*\)\s*\)\s*\|\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*>>>\s*\(\s*32\s*-\s*\(\s*k2\s*\[\s*\d+\s*\]\s*%\s*16\s*\)\s*\)\s*\)',
        ),
        (idx, ki) => re[idx] = _rotl(re[idx], k2[ki] % 16),
      );
      addSeq(
        RegExp(
          r'\w+\s*\[\s*(\d+)\s*\]\s*=\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*<<\s*\(\s*k2\s*\[\s*(\d+)\s*\]\s*%\s*16\s*\)\s*\)\s*\|\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*<<\s*\(\s*32\s*-\s*\(\s*k2\s*\[\s*\d+\s*\]\s*%\s*16\s*\)\s*\)\s*\)',
        ),
        (idx, ki) {
          final n = k2[ki] % 16;
          re[idx] = ((re[idx] << n) | (re[idx] << (32 - n))) & _m32;
        },
      );
      addSeq(
        RegExp(
          r'\w+\s*\[\s*(\d+)\s*\]\s*=\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*>>>\s*\(\s*k2\s*\[\s*(\d+)\s*\]\s*%\s*16\s*\)\s*\)\s*\|\s*\(\s*\w+\s*\[\s*\d+\s*\]\s*<<\s*\(\s*32\s*-\s*\(\s*k2\s*\[\s*\d+\s*\]\s*%\s*16\s*\)\s*\)\s*\)',
        ),
        (idx, ki) => re[idx] = _rotr(re[idx], k2[ki] % 16),
      );
      addSeq(
        RegExp(r'\w+\s*\[\s*(\d+)\s*\]\s*\+=\s*k2\s*\[\s*(\d+)\s*\]'),
        (idx, ki) => re[idx] = (re[idx] + k2[ki]) & _m32,
      );
      addSeq(
        RegExp(r'\w+\s*\[\s*(\d+)\s*\]\s*-=\s*k2\s*\[\s*(\d+)\s*\]'),
        (idx, ki) => re[idx] = (re[idx] - k2[ki]) & _m32,
      );
      addSeq(
        RegExp(r'\w+\s*\[\s*(\d+)\s*\]\s*\^=\s*k2\s*\[\s*(\d+)\s*\]'),
        (idx, ki) => re[idx] = re[idx] ^ k2[ki],
      );

      evs.sort((a, b) => (a[0] as int).compareTo(b[0] as int));
      for (final e in evs) {
        (e[1] as void Function())();
      }

      // hex 输出：每个 int 的每个字节两 nibble 交换
      const hc = '0123456789abcdef';
      final sb = StringBuffer();
      for (final x in re) {
        for (var j = 0; j < 4; j++) {
          sb.write(hc[(x >> (j * 8 + 4)) & 15]);
          sb.write(hc[(x >> (j * 8)) & 15]);
        }
      }
      return 'v=$date&did=$did&tt=$tt&sign=$sb';
    } catch (_) {
      return null;
    }
  }

  /// 入口：script 为 homeH5Enc 返回的 JS。
  /// 返回 null 表示解析失败（调用方应回退）。
  static String? getSign(String script, String rid, String did, int tt) {
    final inner = runShell(script);
    if (inner == null || inner.isEmpty) return null;
    return signInner(inner, rid, did, tt);
  }
}
