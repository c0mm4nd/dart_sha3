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
    });

    test('KECCAK', () {
      var k = SHA3(256, KECCAK_PADDING, 256);
      k.update(utf8.encode('Hello'));
      var hash = k.digest();

      expect(HEX.encode(hash),
          '06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2');
    });

    test('SHAKE', () {
      var k = SHA3(256, SHAKE_PADDING, 256);
      k.update(utf8.encode('Hello'));
      var hash = k.digest();

      expect(HEX.encode(hash),
          '555796c90bfb8f3256a1cb0d7e574877fd48750e4147cf40aa43da122b4d64da');
    });
  });
}
