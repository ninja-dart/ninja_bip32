import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:elliptic/elliptic.dart';
import 'package:ninja/ninja.dart';

List<int> hmacSHA512(List<int> key, List<int> data) {
  final hmac = crypto.Hmac(crypto.sha512, key);
  return hmac.convert(data).bytes;
}

extension IntListToUint8List on List<int> {
  Uint8List toUint8List() => Uint8List.fromList(this);
}

final secp256r1 = getSecp256r1();

Uint8List privateKeyToPublicKey(Uint8List privateKey) {
  final point = secp256r1.scalarMul(secp256r1.G, privateKey);
  final len = secp256r1.bitSize ~/ 8;
  final x = bigIntToBytes(point.X, outLen: len);
  final y = bigIntToBytes(point.Y, outLen: len);
  final bytes = Uint8List(2 * len + 1);
  bytes.setAll(1, x);
  bytes.setAll(len + 1, y);
  return bytes;
}
