import 'package:hdwallet/src/util/util.dart';
import 'package:ninja/ninja.dart';
import 'package:web3dart/web3dart.dart' as web3;
import 'package:web3dart/crypto.dart';

void main() {
  //final privateKeyHex = '58847ec939249843d69b33dbbed2479ec11a72dbd46064e3a5fb620ea1527298';
  //final privateKeyBytes = hexToBytes(privateKeyHex);

  final privateKeyStr = BigInt.parse('23060511436313968293961213416787401598589942588437249589070873527224060136058');
  final privateKeyBytes = bigIntToBytes(privateKeyStr);
  print(privateKeyToPublicKey(privateKeyBytes));

  print(privateKeyBytesToPublic(privateKeyBytes));
}