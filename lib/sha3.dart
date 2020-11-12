library sha3;

import 'src/f.dart';

export 'sha3.dart';

const SHAKE_PADDING = [31, 7936, 2031616, 520093696];
const CSHAKE_PADDING = [4, 1024, 262144, 67108864];
const KECCAK_PADDING = [1, 256, 65536, 16777216];
const SHA3_PADDING = [6, 1536, 393216, 100663296];

const NORMAL_BITS = [224, 256, 384, 512];
const SHAKE_BITS = [128, 256];

const FINALIZE_ERROR = 'finalize already called';

/// A SHA3 has params: int bits, List<int> padding, int outputBits
/// Avaliable `bits`:
///   - for keccak and sha3: use number in `NORMAL_BITS`: [224, 256, 384, 512];
///   - for shake cshake: use number in `SHAKE_BITS`: [128, 256];
/// Avaliable `padding`:
///   - `SHA3_PADDING`: for sha3;
///   - `KECCAK_PADDING`: for keccak;
///   - `SHAKE_PADDING`: for shake;
///   - `CSHAKE_PADDING`: for cshake;
/// Avaliable `outputBits`:
///   same to `bits`;
class SHA3 {
  List<int> blocks;
  List<int> s;
  List<int> padding;
  var reset = true;
  var finalized = false;
  var block = 0;
  var start = 0;
  int blockCount;
  int byteCount;
  int outputBlocks;
  int outputBits;
  int extraBytes;
  int lastByteIndex = 0;

  SHA3(int bits, List<int> padding, int outputBits) {
    this.padding = padding;
    this.outputBits = outputBits;
    blockCount = (1600 - (bits << 1)) >> 5;
    byteCount = blockCount << 2;
    outputBlocks = outputBits >> 5;
    extraBytes = (outputBits & 31) >> 3;

    s = List<int>.filled(50, 0, growable: true);
    blocks = List<int>.filled(blockCount + 1, 0, growable: true);
  }

  // update inputs the ascii/utf8 encoded int array and return the class itself for next step
  SHA3 update(List<int> message) {
    if (finalized) {
      throw Exception(FINALIZE_ERROR);
    }

    var blocks = this.blocks,
        byteCount = this.byteCount,
        length = message.length,
        blockCount = this.blockCount,
        index = 0,
        s = this.s,
        i;

    while (index < length) {
      if (reset) {
        reset = false;
        blocks[0] = block;
        for (i = 1; i < blockCount + 1; ++i) {
          blocks[i] = 0;
        }
      }

      for (i = start; index < length && i < byteCount; ++index) {
        blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
      }

      lastByteIndex = i;
      if (i >= byteCount) {
        start = i - byteCount;
        block = blocks[blockCount];
        for (i = 0; i < blockCount; ++i) {
          s[i] ^= blocks[i];
        }
        f(s);
        reset = true;
      } else {
        start = i;
      }
    }

    return this;
  }

  // encode is not used yet, maybe will be deleted
  int encode(int x, bool right) {
    var o = x & 255, n = 1;
    var bytes = [o];
    x = x >> 8;
    o = x & 255;
    while (o > 0) {
      bytes = unshift(bytes, [o]);
      x = x >> 8;
      o = x & 255;
      ++n;
    }
    if (right) {
      bytes.add(n);
    } else {
      bytes = unshift(bytes, [n]);
    }
    update(bytes);
    return bytes.length;
  }

  // finalize is called by digest
  void finalize() {
    if (finalized) {
      return;
    }

    finalized = true;
    var blocks = this.blocks,
        i = lastByteIndex,
        blockCount = this.blockCount,
        s = this.s;

    blocks[i >> 2] |= padding[i & 3];
    if (lastByteIndex == byteCount) {
      blocks[0] = blocks[blockCount];
      for (var i = 1; i < blockCount + 1; ++i) {
        blocks[i] = 0;
      }
    }

    blocks[blockCount - 1] |= 0x80000000;
    for (var i = 0; i < blockCount; ++i) {
      s[i] ^= blocks[i];
    }
    f(s);
  }

  // digest will sum and return a int list as hash
  List<int> digest() {
    finalize();

    var blockCount = this.blockCount,
        s = this.s,
        outputBlocks = this.outputBlocks,
        extraBytes = this.extraBytes,
        i = 0,
        j = 0;
    var array =
        List<int>.filled((outputBlocks << 2), 0); // final hash Uint8Array
    var offset, block;
    while (j < outputBlocks) {
      for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
        offset = j << 2;
        block = s[i];
        array[offset] = block & 0xFF;
        array[offset + 1] = (block >> 8) & 0xFF;
        array[offset + 2] = (block >> 16) & 0xFF;
        array[offset + 3] = (block >> 24) & 0xFF;
      }
      if (j % blockCount == 0) {
        f(s);
      }
    }
    if (extraBytes > 0) {
      offset = j << 2 & 0xFFFFFFFF;
      block = s[i];
      array[offset] = block & 0xFF;
      if (extraBytes > 1) {
        array[offset + 1] = (block >> 8) & 0xFF;
      }
      if (extraBytes > 2) {
        array[offset + 2] = (block >> 16) & 0xFF;
      }
    }
    return array;
  }
}

/// KMAC: dynamic bits, dynamic padding, dynamic outputBits
/// Avaliable `bits`: use number in `SHAKE_BITS`: [128, 256];
/// Avaliable `padding`: `CSHAKE_PADDING`;
/// Avaliable `outputBits`: same to `bits`;
class KMAC extends SHA3 {
  KMAC(bits, padding, outputBits) : super(bits, padding, outputBits);

  @override
  void finalize() {
    encode(outputBits, true);
    return super.finalize();
  }
}
