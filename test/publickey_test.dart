import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:hdwallet/src/util/util.dart';
import 'package:test/test.dart';

void main() {
  test('privateKeyToPublicKey.Test1', () {
    final privateKey = PrivateKey.fromIntString(
        '23060511436313968293961213416787401598589942588437249589070873527224060136058');
    final publicKey = privateKeyToPublicKey(privateKey.privateKey);
    expect(publicKey.x.toString(),
        '84292017281767030273028310919322695420453506208546052753540575775365448403827');
    expect(publicKey.y.toString(),
        '25904160386613918775823412511929030000549808154747672936073892473649458963862');
  });
  test('privateKeyToPublicKey.Test2', () {
    final privateKey = PrivateKey.fromHexString(
        '58847ec939249843d69b33dbbed2479ec11a72dbd46064e3a5fb620ea1527298');
    final publicKey = privateKeyToPublicKey(privateKey.privateKey);
    expect(publicKey.x.toString(),
        '46946889622425550595700168784404587620473398686614846891534954539888207263255');
    expect(publicKey.y.toString(),
        '5430463959573284168567349079695793523642018960332470148183412286176806162833');
  });
  test('PublicKey.Encode.uncompressed', () {
    final privateKey = PrivateKey.fromHexString(
        '5857b8210951449eb64c3463ac01d9a39f125a3cc30cc6c198c623a6bf2750db');
    final publicKey = privateKeyToPublicKey(privateKey.privateKey);
    final compressedPublic = publicKey.encode(compressed: false);
    expect(compressedPublic,
        '044c4297ed7c208a19efeb12e05f28f37d1826152556a3e1e82fe5c3ed699289de1e2a52777c375302e081116d5528e92aaf0fa77878d6fda73ef2c79076c633e5');
  });
}
