import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:hdwallet/src/util/util.dart';
import 'package:ninja/ninja.dart';
import 'package:web3dart/crypto.dart';
import 'package:secp256k1/src/base.dart' as base;
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
  final Uint8List parentFingerprint;
  final BigInt index;

  ExtendedKeyProps(
      {required this.depth,
      required this.parentFingerprint,
      required this.index});
}

class ExtendedPrivateKey extends PrivateKey {
  final Uint8List chainCode;

  final ExtendedKeyProps? props;

  ExtendedPrivateKey(BigInt privateKey, this.chainCode, {this.props})
      : super(privateKey);

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

  ExtendedPrivateKey generateHardenedChildKey(BigInt index) {
    if (index < hardenBit) {
      throw ArgumentError(
          'index should be greater than or equal to $hardenBit');
    }
    final data = Uint8List(37);
    data[0] = 0x00;
    data.setRange(1, 33, privateKey.toBytes());
    data.setRange(33, 37, index.toBytes(outLen: 4));
    final whole = Uint8List.fromList(hmacSHA512(this.chainCode, data));
    final key =
        (bytesToBigInt(whole.sublist(0, 32)) + privateKey) % base.secp256k1.n;
    final chainCode = whole.sublist(32);
    return ExtendedPrivateKey(key, chainCode);
  }

  ExtendedPublicKey generateNonHardenedChildKey(BigInt index) {
    if (index >= hardenBit) {
      throw ArgumentError('index should be less than $hardenBit');
    }
    final data = Uint8List(37);
    data.setRange(0, 33, publicKey.encodeIntoBytes());
    data.setRange(33, 37, index.toBytes(outLen: 4));
    final whole = Uint8List.fromList(hmacSHA512(this.chainCode, data));
    final key = bytesToBigInt(whole.sublist(0, 32));
    final chainCode = whole.sublist(32);
    // TODO

    throw UnimplementedError();
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
    bytes.setRange(9, 13, props.index.toBytes(outLen: 4));
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
      // TODO
      throw UnimplementedError();
    }
  }

  String encode({bool compressed = true}) =>
      bytesToHex(encodeIntoBytes(compressed: compressed));

  List<int> get fingerprint => ripemd160(encodeIntoBytes());

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
    bytes.setRange(0, 4, [0x04, 0x88, 0xad, 0xe4]);
    bytes[4] = props.depth;
    bytes.setRange(5, 9, props.parentFingerprint);
    bytes.setRange(9, 13, props.index.toBytes(outLen: 4));
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

final hardenBit = BigInt.tryParse('0x80000000', radix: 16)!;
