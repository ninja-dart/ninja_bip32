import 'package:hdwallet/src/bip32/bip32.dart';

void main() {
  final master = ExtendedPrivateKey.deserialize(
      'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73');
  final k = master.deriveHardenedChildKey(0x80000001);
  print(k.serialize());

  // xprv9tzRNW1i8X1PSWBU8w1T7f8xCejSahmGsBLXi2XUqJPF7gLpn99mnuUK9jUKUP9hZbi5bbMCcHKi7MceLJ2ya3ArinuB3rDgcUnSzks1iWk
}
