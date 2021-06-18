import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:hdwallet/src/util/util.dart';

void main() {
  // final privateKey = PrivateKey.fromHexString('58847ec939249843d69b33dbbed2479ec11a72dbd46064e3a5fb620ea1527298').privateKey;
  final privateKey = PrivateKey.fromHexString(
      '5857b8210951449eb64c3463ac01d9a39f125a3cc30cc6c198c623a6bf2750db');

  print(privateKey.publicKey);

  {
    final publicEnc = privateKey.publicKey.encode(compressed: false);
    print(publicEnc);

    final public = PublicKey.decode(publicEnc);
    print(public);
  }

  {
    final publicEnc = privateKey.publicKey.encode();
    print(publicEnc);

    final public = PublicKey.decode(publicEnc);
    print(public);
  }

  print(extendedKeyChecksum(List.generate(32, (index) => 100 + index)));

  print(privateKey.publicKey.fingerprint.toHex());

  /*
  final privateKeyBytes = bigIntToBytes(privateKey);
  final publicKey = privateKeyBytesToPublic(privateKeyBytes);
  print(publicKey);

  print(bytesToBigInt(publicKey).toRadixString(16));
   */
}
