import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:secp256k1/src/base.dart' as base;
import 'package:ninja/ninja.dart';

List<int> hmacSHA512(List<int> key, List<int> data) {
  final hmac = crypto.Hmac(crypto.sha512, key);
  return hmac.convert(data).bytes;
}

extension IntListToUint8List on List<int> {
  Uint8List toUint8List() => Uint8List.fromList(this);
}

PublicKey privateKeyToPublicKey(Uint8List privateKey) {
  final point = base.getPointByBig(bytesToBigInt(privateKey), base.secp256k1.p,
      base.secp256k1.a, base.secp256k1.G);
  return PublicKey(point.first, point.last);
}
