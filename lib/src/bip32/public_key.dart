import 'dart:typed_data';

import 'package:bs58check/bs58check.dart';
import 'package:ninja_bip32/src/bip32/private_key.dart';
import 'package:ninja_bip32/src/util/util.dart';
import 'package:ninja/ninja.dart';
import 'package:secp256k1/src/base.dart' as curve;

class PublicKey {
  final BigInt x;

  final BigInt y;

  PublicKey(this.x, this.y);

  factory PublicKey.decode(String input) {
    if (input.startsWith('04')) {
      if (input.length != 130) {
        throw ArgumentError.value(
            input, 'input', 'invalid public key string: incorrect length');
      }
      final xStr = input.substring(2 * 1, 2 * 33);
      final yStr = input.substring(2 * 33);
      final x = BigInt.parse(xStr, radix: 16);
      final y = BigInt.parse(yStr, radix: 16);
      return PublicKey(x, y);
    } else if (input.startsWith('02') || input.startsWith('03')) {
      if (input.length != 66) {
        throw ArgumentError.value(
            input, 'input', 'invalid public key string: incorrect length');
      }
      final xStr = input.substring(2 * 1);
      final x = BigInt.parse(xStr, radix: 16);
      final ySq = (x.pow(3) + BigInt.from(7)) % curve.secp256k1.p;
      BigInt y = ySq.modPow((curve.secp256k1.p + BigInt.one) ~/ BigInt.from(4),
          curve.secp256k1.p);
      if (input.startsWith('02') && y.isOdd) {
        y = (curve.secp256k1.p - y) % curve.secp256k1.p;
      } else if (input.startsWith('03') && y.isEven) {
        y = (curve.secp256k1.p - y) % curve.secp256k1.p;
      }
      return PublicKey(x, y);
    } else {
      throw ArgumentError.value(input, 'input', 'invalid public key string');
    }
  }

  factory PublicKey.decodeBytes(Iterable<int> bytes, {bool compressed = true}) {
    String str;
    if (compressed) {
      str = bytes.toHex(outLen: 66);
    } else {
      str = bytes.toHex(outLen: 130);
    }
    return PublicKey.decode(str);
  }

  Uint8List encodeIntoBytes({bool compressed = true}) {
    final pointLen = 32;
    final xBytes = bigIntToBytes(x, outLen: pointLen);

    if (!compressed) {
      final yBytes = bigIntToBytes(y, outLen: pointLen);
      final bytes = Uint8List(65);
      bytes[0] = 0x04;
      bytes.setRange(1, 33, xBytes);
      bytes.setRange(33, 65, yBytes);
      return bytes;
    } else {
      final bytes = Uint8List(33);
      if (y.isOdd) {
        bytes[0] = 0x03;
      } else {
        bytes[0] = 0x02;
      }
      bytes.setRange(1, 33, xBytes);
      return bytes;
    }
  }

  String encode({bool compressed = true}) {
    Uint8List bytes = encodeIntoBytes(compressed: compressed);
    if (compressed) {
      return bytes.toHex(outLen: 66);
    } else {
      return bytes.toHex(outLen: 130);
    }
  }

  List<int> get fingerprint => publicKeyFingerprint(encodeIntoBytes());

  String get fingerprintHex => fingerprint.toHex(outLen: 8);

  @override
  String toString() => 'PublicKey($x, $y)';
}

class ExtendedPublicKey extends PublicKey {
  final Uint8List chainCode;
  final ExtendedKeyProps props;

  ExtendedPublicKey(BigInt x, BigInt y, this.chainCode, this.props)
      : super(x, y);

  factory ExtendedPublicKey.fromHexString(
      String keyStr, String chainCodeStr, ExtendedKeyProps props) {
    final publicKey = PublicKey.decode(keyStr);

    final chainCodeInt = BigInt.tryParse(chainCodeStr, radix: 16);
    if (chainCodeInt == null) {
      throw ArgumentError('invalid chain code');
    }
    return ExtendedPublicKey(
        publicKey.x, publicKey.y, chainCodeInt.asBytes(outLen: 32), props);
  }

  factory ExtendedPublicKey.deserialize(String input) {
    if (!input.startsWith('xpub')) {
      throw ArgumentError.value('Invalid xpub');
    }

    final bytes = base58.decode(input);
    if (bytes.length != 82) {
      throw ArgumentError.value('Invalid length');
    }

    final int depth = bytes[4];
    final int index = bytesToBigInt(bytes.getRange(9, 13)).toInt();
    final Uint8List parentFingerprint = Uint8List.fromList(bytes.sublist(5, 9));
    final chainCode = Uint8List.fromList(bytes.sublist(13, 45));
    final publicKeyBytes = bytes.getRange(45, 78);
    final checksum = bytes.getRange(78, 82);

    final publicKey = PublicKey.decodeBytes(publicKeyBytes);

    final ret = ExtendedPublicKey(
      publicKey.x,
      publicKey.y,
      chainCode,
      ExtendedKeyProps(
          depth: depth, parentFingerprint: parentFingerprint, index: index),
    );

    if (!iterableEquality.equals(checksum, ret.checksum())) {
      throw ArgumentError.value('Invalid length');
    }

    return ret;
  }

  String get chainCodeHex => chainCode.toHex(outLen: 64);

  Iterable<int> checksum() {
    final encoded = serializeIntoBytes();
    return encoded.skip(78);
  }

  PublicKey generateChildPublicKey(int index) {
    if (index >= hardenBit) {
      throw ArgumentError('index should be less than $hardenBit');
    }
    final data = Uint8List(37);
    data.setRange(0, 33, encodeIntoBytes());
    data.setRange(33, 37, BigInt.from(index).asBytes(outLen: 4));
    final whole = Uint8List.fromList(hmacSHA512(chainCode, data));

    final il = bytesToBigInt(whole.sublist(0, 32));
    return addScalar(x, y, il);
  }

  Uint8List serializeIntoBytes() {
    final bytes = Uint8List(82);
    bytes.setRange(0, 4, [0x04, 0x88, 0xb2, 0x1e]);
    bytes[4] = props.depth;
    bytes.setRange(5, 9, props.parentFingerprint);
    bytes.setRange(9, 13, BigInt.from(props.index).asBytes(outLen: 4));
    bytes.setRange(13, 45, chainCode);
    final keyBytes = encodeIntoBytes();
    bytes.setRange(45, 78, keyBytes);
    bytes.setRange(78, 82, extendedKeyChecksum(bytes.take(78)));
    return bytes;
  }

  String serialize() {
    final bytes = serializeIntoBytes();
    return base58.encode(bytes).padLeft(64, '0');
  }
}
