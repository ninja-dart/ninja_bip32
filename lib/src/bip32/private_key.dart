import 'dart:convert';
import 'dart:typed_data';
import 'package:bs58check/bs58check.dart';
import 'package:secp256k1/src/base.dart' as curve;

import 'package:ninja_bip32/src/util/util.dart';
import 'package:ninja/ninja.dart';

import 'public_key.dart';

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

  String get parentFingerprintHex => parentFingerprint.toHex(outLen: 8);

  @override
  String toString() => '($depth, $parentFingerprintHex, $index)';
}

class ExtendedPrivateKey extends PrivateKey {
  final Uint8List chainCode;

  final ExtendedKeyProps props;

  ExtendedPrivateKey(BigInt privateKey, this.chainCode, this.props)
      : super(privateKey) {
    if (privateKey.bitLength > 32 * 8) {
      throw Exception('private key too large');
    }
  }

  factory ExtendedPrivateKey.fromHexString(
      String key, String chainCode, ExtendedKeyProps props) {
    final keyInt = BigInt.tryParse(key, radix: 16);
    if (keyInt == null) {
      throw ArgumentError('invalid hex key');
    }
    final chainCodeInt = BigInt.tryParse(chainCode, radix: 16);
    if (chainCodeInt == null) {
      throw ArgumentError('invalid chain code');
    }

    return ExtendedPrivateKey(keyInt, chainCodeInt.toBytes(outLen: 32), props);
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

    final ret = ExtendedPrivateKey(
        privateKey,
        chainCode,
        ExtendedKeyProps(
            depth: depth, parentFingerprint: parentFingerprint, index: index));

    if (!iterableEquality.equals(checksum, ret.checksum())) {
      throw ArgumentError.value('Invalid length');
    }

    return ret;
  }

  String get chainCodeHex => chainCode.toHex(outLen: 64);

  ExtendedPublicKey get extendedPublicKey {
    return ExtendedPublicKey(publicKey.x, publicKey.y, chainCode, props);
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
    return ExtendedPrivateKey(
        key,
        chainCode,
        ExtendedKeyProps(
            depth: props.depth + 1,
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
    final key =
        (bytesToBigInt(whole.sublist(0, 32)) + privateKey) % curve.secp256k1.n;
    final chainCode = whole.sublist(32);
    return ExtendedPrivateKey(
        key,
        chainCode,
        ExtendedKeyProps(
            depth: props.depth + 1,
            parentFingerprint: publicKey.fingerprint,
            index: index));
  }

  Iterable<int> checksum() {
    final encoded = serializeIntoBytes();
    return encoded.skip(78);
  }

  Uint8List serializeIntoBytes() {
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

  String serialize() {
    final bytes = serializeIntoBytes();
    return base58.encode(bytes);
  }

  ExtendedPrivateKey derivePath(String path) {
    if (!pathRegExp.hasMatch(path)) {
      throw ArgumentError.value(path, 'path', 'Invalid path');
    }
    path = path.substring(1);
    final part = path.split('/')[0];
    path = path.substring(part.length);
    ExtendedPrivateKey ret;
    if (part.endsWith("'")) {
      final index =
          int.tryParse(part.substring(0, part.length - 1))! + hardenBit;
      ret = deriveHardenedChildKey(index);
    } else {
      final index = int.tryParse(part)!;
      ret = deriveNonHardenedChildKey(index);
    }
    if (path.isEmpty) {
      return ret;
    }
    return ret.derivePath(path);
  }

  static final pathRegExp = RegExp(r'''^(/[0-9]+'?)*$''');
}

class MasterKey extends ExtendedPrivateKey {
  MasterKey(BigInt privateKey, Uint8List chainCode)
      : super(
            privateKey,
            chainCode,
            ExtendedKeyProps(
                depth: 0, parentFingerprint: [0, 0, 0, 0], index: 0));

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

  factory MasterKey.deserialize(String xprv) {
    final xp = ExtendedPrivateKey.deserialize(xprv);

    if (xp.props.depth != 0) {
      throw Exception('Invalid depth');
    }

    if (xp.props.index != 0) {
      throw Exception('Invalid index');
    }

    if (xp.props.parentFingerprintHex != '00000000') {
      throw Exception('Invalid parent fingerprint');
    }

    return MasterKey(xp.privateKey, xp.chainCode);
  }

  @override
  ExtendedPrivateKey derivePath(String path) {
    if (!pathRegExp.hasMatch(path)) {
      throw ArgumentError.value(path, 'path', 'Invalid path');
    }
    if (path == 'm') {
      return this;
    }
    path = path.substring(2);
    final part = path.split('/')[0];
    path = path.substring(part.length);
    ExtendedPrivateKey ret;
    if (part.endsWith("'")) {
      final index =
          int.tryParse(part.substring(0, part.length - 1))! + hardenBit;
      ret = deriveHardenedChildKey(index);
    } else {
      final index = int.tryParse(part)!;
      ret = deriveNonHardenedChildKey(index);
    }
    if (path.isEmpty) {
      return ret;
    }
    return ret.derivePath(path);
  }

  static final pathRegExp = RegExp(r'''^m(/[0-9]+'?)*$''');
}
