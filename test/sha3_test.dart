import 'dart:convert';

import 'package:hex/hex.dart';
import 'package:sha3/sha3.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    // Keccak k;

    setUp(() {
      
    });

    test('First Test', () {
      var k = SHA3(256, KECCAK_PADDING, 256);
      k.update(utf8.encode('Hello'));
      var hash = k.digest();

      expect(HEX.encode(hash), '06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2');
      
      k = SHA3(256, SHA3_PADDING, 256);
      k.update(utf8.encode('Hello'));
      hash = k.digest();

      expect(HEX.encode(hash), '8ca66ee6b2fe4bb928a8e3cd2f508de4119c0895f22e011117e22cf9b13de7ef');
    });

    test('Test unshift', () {
      var bytes = [1,2,3,4];
      var h = [0];
      var new_array = unshift(bytes, h);
      expect(new_array, [0,1,2,3,4  ]);
    });
  });
}
