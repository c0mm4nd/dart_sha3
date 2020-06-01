import 'dart:convert';

import 'package:hex/hex.dart';
import 'package:sha3/sha3.dart';

void main() {
  /* SHA3(int bits, List<int> padding, int outputBits)
    Avaliable `bits`: 
      - for keccak and sha3: use number in `NORMAL_BITS`: [224, 256, 384, 512];
      - for shake cshake: use number in `SHAKE_BITS`: [128, 256];

    Avaliable `padding`:
      - SHA3_PADDING: for sha3;
      - KECCAK_PADDING: for keccak;
      - SHAKE_PADDING: for shake;
      - CSHAKE_PADDING: for cshake;

    Avaliable `outputBits`:
      same to `bits`;
   */
  var k = SHA3(256, KECCAK_PADDING, 256);
  k.update(utf8.encode('Hello'));
  var hash = k.digest();
  print(HEX.encode(
      hash)); // 06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2

  /* KMAC(dynamic bits, dynamic padding, dynamic outputBits)
    Avaliable `bits`: use number in `SHAKE_BITS`: [128, 256];
    Avaliable `padding`: CSHAKE_PADDING;
    Avaliable `outputBits`: same to `bits`;
   */
  var kmac = KMAC(256, CSHAKE_PADDING, 256);
  kmac.update(utf8.encode('Hello'));
  var kmac_hash = kmac.digest();
  print(HEX.encode(kmac_hash));
}
