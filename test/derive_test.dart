import 'package:ninja_bip32/src/bip32/bip32.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

void main() {
  test('derivePath', () {
    final master = MasterKey.deserialize(
        'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73');
    expect(master.derivePath('m').serialize(),
        'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73');

    // Depth 1
    expect(master.derivePath('m/0').serialize(),
        'xprv9tzRNW1ZnrURDnTFnvwECWXtjDBmUC1SoEwCqnYsoZTUHWpeWPRWhYXkGApgPrQBYZpE31yx89iwMBrKJ8ihEdcpSwRPNcPrdxuzCZ7Fwek');
    expect(master.derivePath("m/0'").serialize(),
        'xprv9tzRNW1i8X1PQtcefmtv3MTaUq4CeQ8LSn46H3hJ95C8TeWBZKSqmG6MoxC6X9Di7ePSdc6jgY2Zb3YeYNkeEBKCu7C7HDNbn3dCnMa6pcz');

    // Depth 2
    expect(master.derivePath('m/0/0').serialize(),
        'xprv9xDfxS6Lqhq1BMdoYro8rAvPFBxcavKgZwEaieWYrFYfU2Cts9y1vSSYEDts7WR2wR2g91w2kiANVyDNmCd8GaWLNgmeqvNHuW1m4Nom9KM');
    expect(master.derivePath("m/0'/0").serialize(),
        'xprv9wHokC2KXdTSpEepFcu53hMDUHYfAtTaLEJEMyxBPAMf78hJg17WhL5FyeDUQH5KWmGjGgEb2j74gsZqgupWpPbZgP6uFmP8MYEy5BNbyET');
  });
}
