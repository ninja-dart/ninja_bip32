import 'dart:collection';

import 'package:ninja_bip32/src/bip32/bip32.dart';
import 'package:test/expect.dart';
import 'package:test/scaffolding.dart';

class _TestCase {
  final String parent;

  /// https://bip32jp.github.io/english/
  final LinkedHashMap<int, String> children;

  _TestCase(this.parent, this.children);

  void execute() {
    final master = ExtendedPrivateKey.deserialize(parent);
    for (final index in children.keys) {
      final k = master.deriveNonHardenedChildKey(index);
      expect(k.serialize(), children[index]);
    }
  }
}

void main() {
  test('Derive.NonHardened', () {
    var tc = _TestCase(
      'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73',
      LinkedHashMap()
        ..[0] =
            'xprv9tzRNW1ZnrURDnTFnvwECWXtjDBmUC1SoEwCqnYsoZTUHWpeWPRWhYXkGApgPrQBYZpE31yx89iwMBrKJ8ihEdcpSwRPNcPrdxuzCZ7Fwek'
      /*..[0x80000001] =
            'xprv9tzRNW1i8X1PSWBU8w1T7f8xCejSahmGsBLXi2XUqJPF7gLpn99mnuUK9jUKUP9hZbi5bbMCcHKi7MceLJ2ya3ArinuB3rDgcUnSzks1iWk'
        ..[2166572391] =
            'xprv9tzRNW1iCpN2U7HMw8P17utGzeU6AzHnoxMYTeJYq1YDUmkoNDb4t26n9ypAWLkmd3iWaHNEp7nhV1uFn9KSfyFWtAbzpxTK1o4pDKXKHsa'
        ..[4294967295] =
            'xprv9tzRNW1rUBYMXgik75Kw6ofL9ZEjn9b7cYHNgBwE8isjCPXcYaZmvhJRThs4mugGZeehk7b6p34eBpv36dor6nYXXhM2fF5KCZ6ejqje2Sv'*/
      ,
    );
    tc.execute();
  });
}
