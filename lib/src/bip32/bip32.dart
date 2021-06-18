import 'dart:convert';
import 'dart:typed_data';

import 'package:hdwallet/src/util/util.dart';
import 'package:ninja/ninja.dart';
import 'package:web3dart/crypto.dart';
import 'package:secp256k1/src/base.dart' as curve;
import 'package:bs58check/bs58check.dart';

class PrivateKey {
  final BigInt privateKey;
  late PublicKey publicKey;

  PrivateKey(this.privateKey) {
    publicKey = privateKeyToPublicKey(privateKey);
  }

  factory PrivateKey.fromIntString(String intString) {
    final privateKey = BigInt.tryParse(intString);
    if (privateKey == null) {
      throw ArgumentError('Invalid int string');
    }

    return PrivateKey(privateKey);
  }

  factory PrivateKey.fromHexString(String intString) {
    final privateKey = BigInt.tryParse(intString, radix: 16);
    if (privateKey == null) {
      throw ArgumentError('Invalid int string');
    }

    return PrivateKey(privateKey);
  }

  factory PrivateKey.fromBytes(Iterable<int> bytes) {
    return PrivateKey(bytesToBigInt(bytes));
  }
}

class ExtendedKeyProps {
  final int depth;
  final List<int> parentFingerprint;
  final int index;

  ExtendedKeyProps(
      {required this.depth,
      required this.parentFingerprint,
      required this.index});
}

class ExtendedPrivateKey extends PrivateKey {
  final Uint8List chainCode;

  final ExtendedKeyProps? props;

  ExtendedPrivateKey(BigInt privateKey, this.chainCode, {this.props})
      : super(privateKey) {
    if (privateKey.bitLength > 32 * 8) {
      throw Exception('private key too large');
    }
  }

  factory ExtendedPrivateKey.fromHexString(String key, String chainCode,
      {ExtendedKeyProps? props}) {
    final keyInt = BigInt.tryParse(key, radix: 16);
    if (keyInt == null) {
      throw ArgumentError('invalid hex key');
    }
    final chainCodeInt = BigInt.tryParse(chainCode, radix: 16);
    if (chainCodeInt == null) {
      throw ArgumentError('invalid chain code');
    }

    return ExtendedPrivateKey(keyInt, chainCodeInt.toBytes(outLen: 32),
        props: props);
  }

  factory ExtendedPrivateKey.deserialize(String input) {
    if (!input.startsWith('xprv')) {
      throw ArgumentError.value('Invalid xprv');
    }

    final bytes = base58.decode(input);
    if (bytes.length != 82) {
      throw ArgumentError.value('Invalid length');
    }

    final int depth = bytes[4];
    final int index = bytesToBigInt(bytes.getRange(9, 13)).toInt();
    final Uint8List parentFingerprint = Uint8List.fromList(bytes.sublist(5, 9));
    final chainCode = Uint8List.fromList(bytes.sublist(13, 45));
    final privateKey = bytesToBigInt(bytes.getRange(46, 78));
    final checksum = bytes.getRange(78, 82);

    final ret = ExtendedPrivateKey(privateKey, chainCode,
        props: ExtendedKeyProps(
            depth: depth, parentFingerprint: parentFingerprint, index: index));

    if (!iterableEquality.equals(checksum, ret.checksum())) {
      throw ArgumentError.value('Invalid length');
    }

    return ret;
  }

  /// https://learnmeabitcoin.com/technical/extended-keys
  ExtendedPrivateKey deriveHardenedChildKey(int index) {
    if (index < hardenBit) {
      throw ArgumentError(
          'index should be greater than or equal to $hardenBit');
    }
    final data = Uint8List(37);
    data[0] = 0x00;
    data.setRange(1, 33, privateKey.toBytes());
    data.setRange(33, 37, BigInt.from(index).toBytes(outLen: 4));
    final whole = Uint8List.fromList(hmacSHA512(this.chainCode, data));
    final key =
        (bytesToBigInt(whole.sublist(0, 32)) + privateKey) % curve.secp256k1.n;
    final chainCode = whole.sublist(32);
    return ExtendedPrivateKey(key, chainCode,
        props: ExtendedKeyProps(
            depth: props!.depth + 1,
            parentFingerprint: publicKey.fingerprint,
            index: index));
  }

  ExtendedPrivateKey deriveNonHardenedChildKey(int index) {
    if (index >= hardenBit) {
      throw ArgumentError('index should be less than $hardenBit');
    }
    final data = Uint8List(37);
    data.setRange(0, 33, publicKey.encodeIntoBytes());
    data.setRange(33, 37, BigInt.from(index).toBytes(outLen: 4));
    final whole = Uint8List.fromList(hmacSHA512(this.chainCode, data));
    final key = bytesToBigInt(whole.sublist(0, 32));
    final chainCode = whole.sublist(32);
    return ExtendedPrivateKey(key, chainCode,
        props: ExtendedKeyProps(
            depth: props!.depth + 1,
            parentFingerprint: publicKey.fingerprint,
            index: index));
  }

  Iterable<int> checksum({ExtendedKeyProps? props}) {
    final encoded = serializeIntoBytes(props: props);
    return encoded.skip(78);
  }

  Uint8List serializeIntoBytes({ExtendedKeyProps? props}) {
    props ??= this.props;
    if (props == null) {
      throw Exception('props not found');
    }
    final bytes = Uint8List(82);
    bytes.setRange(0, 4, [0x04, 0x88, 0xad, 0xe4]);
    bytes[4] = props.depth;
    bytes.setRange(5, 9, props.parentFingerprint);
    bytes.setRange(9, 13, BigInt.from(props.index).toBytes(outLen: 4));
    bytes.setRange(13, 45, chainCode);
    final keyBytes = privateKey.toBytes(outLen: 33);
    bytes.setRange(45, 78, keyBytes);
    bytes.setRange(78, 82, extendedKeyChecksum(bytes.take(78)));
    return bytes;
  }

  String serialize({ExtendedKeyProps? props}) {
    final bytes = serializeIntoBytes(props: props);
    return base58.encode(bytes);
  }
}

class MasterKey extends ExtendedPrivateKey {
  MasterKey(BigInt key, Uint8List chainCode) : super(key, chainCode);

  factory MasterKey.fromSeed(Uint8List seed,
      {/* String | List<int> */ salt = 'Bitcoin seed'}) {
    if (seed.length < 16) {
      throw ArgumentError('Seed should be at least 128 bits');
    }
    if (seed.length > 64) {
      throw ArgumentError('Seed should be at most 512 bits');
    }
    if (salt is String) {
      salt = utf8.encode(salt);
    }
    if (salt is! List<int>) {
      throw ArgumentError(
          'salt should be either String or List<int>. got ${salt.runtimeType.toString()}');
    }
    final whole = hmacSHA512(salt, seed);
    final key = bytesToBigInt(whole.sublist(0, 32));
    final chainCode = whole.sublist(32).toUint8List();
    return MasterKey(key, chainCode);
  }
  // TODO
}

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

  String encode({bool compressed = true}) =>
      bytesToHex(encodeIntoBytes(compressed: compressed));

  List<int> get fingerprint => publicKeyFingerprint(encodeIntoBytes());

  @override
  String toString() => 'PublicKey($x, $y)';
}

class ExtendedPublicKey extends PublicKey {
  final Uint8List chainCode;
  final ExtendedKeyProps? props;

  ExtendedPublicKey(BigInt x, BigInt y, this.chainCode, {this.props})
      : super(x, y);

  Uint8List serializeIntoBytes({ExtendedKeyProps? props}) {
    props ??= this.props;
    if (props == null) {
      throw Exception('props not found');
    }
    final bytes = Uint8List(82);
    bytes.setRange(0, 4, [0x04, 0x88, 0xb2, 0x1e]);
    bytes[4] = props.depth;
    bytes.setRange(5, 9, props.parentFingerprint);
    bytes.setRange(9, 13, BigInt.from(props.index).toBytes(outLen: 4));
    bytes.setRange(13, 45, chainCode);
    final keyBytes = encodeIntoBytes();
    bytes.setRange(45, 78, keyBytes);
    bytes.setRange(78, 82, extendedKeyChecksum(bytes.take(78)));
    return bytes;
  }

  String serialize({ExtendedKeyProps? props}) {
    final bytes = serializeIntoBytes(props: props);
    return base58.encode(bytes);
  }
}
