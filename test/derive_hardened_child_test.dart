import 'dart:collection';

import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

class _TestCase {
  final String parent;
  final LinkedHashMap<int, String> children;

  _TestCase(this.parent, this.children);

  void execute() {
    final master = ExtendedPrivateKey.deserialize(
        'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73');
    final k = master.deriveHardenedChildKey(0x80000000);
    // https://bip32jp.github.io/english/
    expect(k.serialize(),
        'xprv9tzRNW1i8X1PQtcefmtv3MTaUq4CeQ8LSn46H3hJ95C8TeWBZKSqmG6MoxC6X9Di7ePSdc6jgY2Zb3YeYNkeEBKCu7C7HDNbn3dCnMa6pcz');
  }
}

void main() {
  test('Derive.Hardened', () {
    final master = ExtendedPrivateKey.deserialize(
        'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73');
    final k = master.deriveHardenedChildKey(0x80000000);
    // https://bip32jp.github.io/english/
    expect(k.serialize(),
        'xprv9tzRNW1i8X1PQtcefmtv3MTaUq4CeQ8LSn46H3hJ95C8TeWBZKSqmG6MoxC6X9Di7ePSdc6jgY2Zb3YeYNkeEBKCu7C7HDNbn3dCnMa6pcz');
  });
}
