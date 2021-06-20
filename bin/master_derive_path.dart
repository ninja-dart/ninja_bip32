import 'package:hdwallet/src/bip32/bip32.dart';

void main() {
  final master = MasterKey.deserialize(
      'xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73');
  print(master.derivePath('m').serialize());
  print(master.derivePath('m/0').serialize());
  print(master.derivePath("m/0'").serialize());
}
