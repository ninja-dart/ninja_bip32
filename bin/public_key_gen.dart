import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:ninja/ninja.dart';
import 'package:web3dart/web3dart.dart' as web3;
import 'package:web3dart/crypto.dart';

void main() {
  // final privateKey = PrivateKey.fromHexString('58847ec939249843d69b33dbbed2479ec11a72dbd46064e3a5fb620ea1527298').privateKey;
  final privateKey = PrivateKey.fromIntString(
          '23060511436313968293961213416787401598589942588437249589070873527224060136058')
      .privateKey;

  final privateKeyBytes = bigIntToBytes(privateKey);
  print(privateKeyBytesToPublic(privateKeyBytes));
}
