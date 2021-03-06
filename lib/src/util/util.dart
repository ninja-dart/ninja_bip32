import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:ninja_bip32/src/bip32/bip32.dart';
import 'package:secp256k1/src/base.dart' as curve;
import 'package:ninja/ninja.dart';

List<int> hmacSHA512(List<int> key, List<int> data) {
  final hmac = crypto.Hmac(crypto.sha512, key);
  return hmac.convert(data).bytes;
}

extension IntIterableToUint8List on Iterable<int> {
  Uint8List toUint8List() => Uint8List.fromList(toList());
}

/*
extension IntListToUint8List on List<int> {
  Uint8List toUint8List() => Uint8List.fromList(this);

  String toHex({int? outLen}) {
    String ret = bytesToBigInt(this).toRadixString(16);
    ret = ret.padLeft(outLen ?? 0, '0');
    return ret;
  }
}

extension Uint8ListTo on Uint8List {
  String toHex({int? outLen}) {
    String ret = bytesToBigInt(this).toRadixString(16);
    ret = ret.padLeft(outLen ?? 0, '0');
    return ret;
  }
}

extension BigIntExt on BigInt {
  Uint8List toBytes({int? outLen}) => bigIntToBytes(this, outLen: outLen);
}*/

PublicKey privateKeyToPublicKey(BigInt privateKey) {
  final point = curve.getPointByBig(
      privateKey, curve.secp256k1.p, curve.secp256k1.a, curve.secp256k1.G);
  return PublicKey(point.first, point.last);
}

Uint8List extendedKeyChecksum(Iterable<int> data) {
  final intermediate = crypto.sha256.convert(data.toList()).bytes;
  final result = crypto.sha256.convert(intermediate).bytes;
  return result.sublist(0, 4).toUint8List();
}

List<int> publicKeyFingerprint(List<int> compressedPubKey) {
  final intermediate1 = crypto.sha256.convert(compressedPubKey).bytes;
  return ripemd160.convert(intermediate1).bytes.sublist(0, 4);
}

final hardenBit = 0x80000000;

final iterableEquality = IterableEquality();

PublicKey addScalar(BigInt x1, BigInt y1, BigInt scalar) {
  final p1 = curve.getPointByBig(
      scalar, curve.secp256k1.p, curve.secp256k1.a, curve.secp256k1.G);
  final ret = curve.addDiffPoint(x1, y1, p1.first, p1.last, curve.secp256k1.p);
  return PublicKey(ret.first, ret.last);
}
