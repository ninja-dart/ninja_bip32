import 'package:ninja_bip32/src/bip32/bip32.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';
import 'package:ninja/ninja.dart';

class _TestCase {
  final String public;
  final String chainCode;
  final ExtendedKeyProps props;

  final String xpub;

  _TestCase(
      {required this.public,
      required this.chainCode,
      required this.props,
      required this.xpub});

  void execute() {
    {
      final key = ExtendedPublicKey.fromHexString(public, chainCode, props);
      expect(key.serialize(), xpub);
    }

    {
      final key = ExtendedPublicKey.deserialize(xpub);
      expect(key.encode(), public);
      expect(key.chainCodeHex, chainCode);
      expect(key.props.index, props.index);
      expect(key.props.depth, props.depth);
      expect(key.props.parentFingerprint, props.parentFingerprint);
    }
  }
}

void main() {
  test('ExtendedPublicKey.serialization', () {
    _TestCase(
            public:
                '03146846eeb5a7533abb594ba734bc243fc7b6349499b8311c8fc13b0112ba8a77',
            chainCode:
                '5aa0e3aab3a704c13b5cca8c98a3be5597c448038ea51add29a9bf66178a85c4',
            props: ExtendedKeyProps(
                depth: 1,
                parentFingerprint:
                    BigInt.parse('0c5f9a1e', radix: 16).asBytes(outLen: 4),
                index: 0),
            xpub:
                'xpub67ymn1YTdE2iSGXitxUEZeUdHF2FsejJATroeAxVMtzTAK9o3vjmFLrE7TqE1X76iobkVc3p8h3gNzNRTwPeQGYW3CCmYCG8n5ThVkXaQzs')
        .execute();
  });
}
