import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:hdwallet/src/util/util.dart';
import 'package:test/test.dart';

class _TestCase {
  final String private;

  final String pubX;

  final String pubY;

  /// https://learnmeabitcoin.com/technical/public-key
  final String uncompressedPub;

  /// https://learnmeabitcoin.com/technical/public-key
  final String compressedPub;

  _TestCase(
      {required this.private,
      required this.pubX,
      required this.pubY,
      required this.uncompressedPub,
      required this.compressedPub});
}

void execute(_TestCase tc) {
  final privateKey = PrivateKey.fromHexString(tc.private);
  final publicKey = privateKeyToPublicKey(privateKey.privateKey);
  expect(publicKey.x.toString(), tc.pubX);
  expect(publicKey.y.toString(), tc.pubY);
  final uncompressedPublic = publicKey.encode(compressed: false);
  expect(uncompressedPublic, tc.uncompressedPub);
  final compressedPublic = publicKey.encode();
  expect(compressedPublic, tc.compressedPub);
}

void main() {
  test('PublicKey.even', () {
    final tc = _TestCase(
        private:
            '32FBC97493634C8B7606BA4D858CF56FD7AAE223C750D7AA1712E4837034CA7A',
        pubX:
            '84292017281767030273028310919322695420453506208546052753540575775365448403827',
        pubY:
            '25904160386613918775823412511929030000549808154747672936073892473649458963862',
        uncompressedPub:
            '04ba5b97518dc64975e0cd27f39217d65eda6f26b77d1b7efeb18a16315f890b7339453c36581eab92f34b0955427039b113770f3aed96898af6f336090be9e596',
        compressedPub:
            '02ba5b97518dc64975e0cd27f39217d65eda6f26b77d1b7efeb18a16315f890b73');

    execute(tc);
  });
  test('PublicKey.odd', () {
    final tc = _TestCase(
        private:
            '58847ec939249843d69b33dbbed2479ec11a72dbd46064e3a5fb620ea1527298',
        pubX:
            '46946889622425550595700168784404587620473398686614846891534954539888207263255',
        pubY:
            '5430463959573284168567349079695793523642018960332470148183412286176806162833',
        uncompressedPub:
            '0467caff756e7310c85d4f8a9a75fa46a8e958c58de1c76d84e612ac979000f6170c01889f3308fdadbde500eaa60ff9a2395ea077773709f6bcd22eefbd51d191',
        compressedPub:
            '0367caff756e7310c85d4f8a9a75fa46a8e958c58de1c76d84e612ac979000f617');

    execute(tc);
  });
}
