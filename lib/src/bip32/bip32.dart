import 'dart:convert';
import 'dart:typed_data';

import 'package:hdwallet/src/util/util.dart';
import 'package:ninja/ninja.dart';
import 'package:web3dart/crypto.dart';

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

class ExtendedPrivateKey extends PrivateKey {
  final Uint8List chainCode;

  ExtendedPrivateKey(BigInt privateKey, this.chainCode) : super(privateKey);

  ExtendedPrivateKey generateHardenedChildKey(int index) {
    if (index < hardenBit) {
      throw ArgumentError(
          'index should be greater than or equal to $hardenBit');
    }
    final data = Uint8List(37);
    data[0] = 0x00;
    data.setRange(1, 33, privateKey.toBytes());
    data.buffer.asByteData().setUint32(33, index);
    final whole = Uint8List.fromList(hmacSHA512(this.chainCode, data));
    final key = bytesToBigInt(whole.sublist(0, 32));
    final chainCode = whole.sublist(32);
    // TODO check that key is less than G
    // TODO check that chainCode is less than G
    return ExtendedPrivateKey(key, chainCode);
  }

  ExtendedPublicKey generateNonHardenedChildKey(int index) {
    if (index >= hardenBit) {
      throw ArgumentError('index should be less than $hardenBit');
    }
    // TODO

    throw UnimplementedError();
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

  String encode({bool compressed = true}) {
    final pointLen = 32;
    final xBytes = bigIntToBytes(x, outLen: pointLen);

    if(!compressed) {
      final yBytes = bigIntToBytes(y, outLen: pointLen);
      final bytes = Uint8List(2 * pointLen + 1);
      bytes[0] = 0x04;
      bytes.setAll(1, xBytes);
      bytes.setAll(pointLen + 1, yBytes);
      return bytesToHex(bytes);
    } else {
      // TODO
      throw UnimplementedError();
    }
  }

  @override
  String toString() => 'PublicKey($x, $y)';
}

class ExtendedPublicKey extends PublicKey {
  ExtendedPublicKey(BigInt x, BigInt y) : super(x, y);
  // TODO
}

const hardenBit = 0x80000000;
