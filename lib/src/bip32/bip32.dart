import 'dart:convert';
import 'dart:typed_data';

import 'package:ethhdwallet/src/util/util.dart';

class ExtendedPrivateKey {
  final Uint8List privateKey;
  final Uint8List chainCode;
  late Uint8List publicKey;

  ExtendedPrivateKey(this.privateKey, this.chainCode) {
    publicKey = privateKeyToPublicKey(privateKey);
  }

  ExtendedPrivateKey generateHardenedChildKey(int index) {
    if(index < hardenBit) {
      throw ArgumentError('index should be greater than or equal to $hardenBit');
    }
    final data = Uint8List(37);
    data[0] = 0x00;
    data.setRange(1, 33, privateKey);
    data.buffer.asByteData().setUint32(33, index);
    final whole = hmacSHA512(this.chainCode, data);
    final key = whole.sublist(0, 32).toUint8List();
    final chainCode = whole.sublist(32).toUint8List();
    // TODO check that key is less than G
    // TODO check that chainCode is less than G
    return ExtendedPrivateKey(key, chainCode);
  }

  ExtendedPublicKey generateNonHardenedChildKey(int index) {
    if(index >= hardenBit) {
      throw ArgumentError('index should be less than $hardenBit');
    }
    // TODO

    throw UnimplementedError();
  }
}

class MasterKey extends ExtendedPrivateKey {
  MasterKey(Uint8List key, Uint8List chainCode) : super(key, chainCode);

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
    final key = whole.sublist(0, 32).toUint8List();
    final chainCode = whole.sublist(32).toUint8List();
    return MasterKey(key, chainCode);
  }
  // TODO
}

class ExtendedPublicKey {
  // TODO
}

const hardenBit = 0x80000000;