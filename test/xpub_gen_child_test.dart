import 'package:ninja_bip32/src/bip32/bip32.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

class _TestCase {
  final String parentXprv;

  final int index;

  _TestCase({required this.parentXprv, required this.index});

  void execute() {
    final xprv = ExtendedPrivateKey.deserialize(parentXprv);
    final prv = xprv.deriveNonHardenedChildKey(index);

    final xpub = xprv.extendedPublicKey;
    expect(xpub.generateChildPublicKey(index).encode(), prv.publicKey.encode());
  }
}

void main() {
  test('ExtendedPublicKey.GenChild', () {
    _TestCase(
            parentXprv:
                'xprv9tzRNW1ZnrURDnTFnvwECWXtjDBmUC1SoEwCqnYsoZTUHWpeWPRWhYXkGApgPrQBYZpE31yx89iwMBrKJ8ihEdcpSwRPNcPrdxuzCZ7Fwek',
            index: 1)
        .execute();
  });
}
