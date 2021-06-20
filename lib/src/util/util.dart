import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:secp256k1/src/base.dart' as curve;
import 'package:ninja/ninja.dart';
import 'package:hash/hash.dart' as hasher;

List<int> hmacSHA512(List<int> key, List<int> data) {
  final hmac = crypto.Hmac(crypto.sha512, key);
  return hmac.convert(data).bytes;
}

extension IntListToUint8List on List<int> {
  Uint8List toUint8List() => Uint8List.fromList(this);

  String toHex({int? outLen}) {
    String ret = bytesToBigInt(this).toRadixString(16);
    ret = ret.padLeft(outLen ?? 0, '0');
    return ret;
  }
}

extension BigIntExt on BigInt {
  Uint8List toBytes({int? outLen}) => bigIntToBytes(this, outLen: outLen);
}

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

Uint8List ripemd160(List<int> msg) =>
    (hasher.RIPEMD160()..update(msg)).digest();

List<int> publicKeyFingerprint(List<int> compressedPubKey) {
  final intermediate1 = crypto.sha256.convert(compressedPubKey).bytes;
  return ripemd160(intermediate1).sublist(0, 4);
}

final hardenBit = 0x80000000;

final iterableEquality = IterableEquality();
