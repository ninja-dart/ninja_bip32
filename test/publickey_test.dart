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
    var tc = _TestCase(
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

    tc = _TestCase(
        private:
            '6beeba626fa9a6320a4ffcea8b30acf7cc0ba7fb093cb48e7f1bb3b79c12da1e',
        pubX:
            '71685586975036526303708132126654111482401973205047258899869042442830029274240',
        pubY:
            '15189089399842232112061480738222192787539749247183499808024132542644402348880',
        uncompressedPub:
            '049e7c9ab93c03fcf4e5ac3b3e532ca7065d8eb67e6a7ac4f950a9748d8b7c3c802194b84e409a9d0517657eeb2ab3a648931aecf1827ff24283f71663fa916350',
        compressedPub:
            '029e7c9ab93c03fcf4e5ac3b3e532ca7065d8eb67e6a7ac4f950a9748d8b7c3c80');

    execute(tc);
  });
  test('PublicKey.odd', () {
    var tc = _TestCase(
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

    tc = _TestCase(
        private:
            '6274de96131b3701f65206f3ec58fb1b8f68638e966b8a0e05f36c045e553b3b',
        pubX:
            '98275443334884765588029941503866365196178012715477497871187118113570423035539',
        pubY:
            '1045484316431219942104305911817598231536463836784799561275136573114178996325',
        uncompressedPub:
            '04d945ee04cafa00a21d6facfce56bdb000689f4379951f21a404c04c8f1a3d693024fb92091cd516598005d63bb253d64b89e4f70540a54ab58be815ec08e0865',
        compressedPub:
            '03d945ee04cafa00a21d6facfce56bdb000689f4379951f21a404c04c8f1a3d693');

    execute(tc);
  });
}
