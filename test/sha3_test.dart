import 'dart:convert';

import 'package:hex/hex.dart';
import 'package:sha3/sha3.dart';
import 'package:test/test.dart';

void main() {
  group('SHA3 Hash Tests', () {
    setUp(() {});

    test('SHA3', () {
      var k = SHA3(256, SHA3_PADDING, 256);
      k.update(utf8.encode('Hello'));
      var hash = k.digest();

      expect(HEX.encode(hash),
          '8ca66ee6b2fe4bb928a8e3cd2f508de4119c0895f22e011117e22cf9b13de7ef');

      var k1 = SHA3(256, SHA3_PADDING, 256);
      expect(utf8.encode(''), []);
      k1.update(utf8.encode(''));
      hash = k1.digest();
      expect(HEX.encode(hash),
          'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');

      var k2 = SHA3(256, SHA3_PADDING, 256);
      k2.update(utf8.encode('Hello World'));
      hash = k2.digest();

      expect(HEX.encode(hash),
          'e167f68d6563d75bb25f3aa49c29ef612d41352dc00606de7cbd630bb2665f51');
    });

    test('KECCAK', () {
      var k = SHA3(256, KECCAK_PADDING, 256);
      k.update(utf8.encode('Hello'));
      var hash = k.digest();

      expect(HEX.encode(hash),
          '06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2');

      var k1 = SHA3(256, KECCAK_PADDING, 256);
      expect(utf8.encode(''), []);
      k1.update(utf8.encode(''));
      hash = k1.digest();
      expect(HEX.encode(hash),
          'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    });

    test('SHAKE', () {
      var k = SHA3(256, SHAKE_PADDING, 256);
      k.update(utf8.encode('Hello'));
      var hash = k.digest();

      expect(HEX.encode(hash),
          '555796c90bfb8f3256a1cb0d7e574877fd48750e4147cf40aa43da122b4d64da');

      var k1 = SHA3(256, SHAKE_PADDING, 256);
      expect(utf8.encode(''), []);
      k1.update(utf8.encode(''));
      hash = k1.digest();
      expect(HEX.encode(hash),
          '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f');
    });
  });
}
