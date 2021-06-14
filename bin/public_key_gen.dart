import 'package:web3dart/web3dart.dart' as web3;
import 'package:ethhdwallet/src/util/util.dart';
import 'package:web3dart/crypto.dart';

void main() {
  final privateKeyHex = '58847ec939249843d69b33dbbed2479ec11a72dbd46064e3a5fb620ea1527298';
  final privateKeyBytes = hexToBytes(privateKeyHex);
  print(privateKeyToPublicKey(privateKeyBytes));

  print(privateKeyBytesToPublic(privateKeyBytes));
}