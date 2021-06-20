import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:test/expect.dart';

void main(List<String> arguments) {
  final xprv = ExtendedPrivateKey.deserialize(
      'xprv9tzRNW1ZnrURDnTFnvwECWXtjDBmUC1SoEwCqnYsoZTUHWpeWPRWhYXkGApgPrQBYZpE31yx89iwMBrKJ8ihEdcpSwRPNcPrdxuzCZ7Fwek');
  final prv = xprv.deriveNonHardenedChildKey(1);
  print(prv.publicKey.encode());

  final xpub = xprv.extendedPublicKey;
  print(xpub.encode());
  print(xpub.chainCodeHex);
  // print(xpub.serialize());
  // print(xpub.serialize() == 'xpub67ymn1YTdE2iSGXitxUEZeUdHF2FsejJATroeAxVMtzTAK9o3vjmFLrE7TqE1X76iobkVc3p8h3gNzNRTwPeQGYW3CCmYCG8n5ThVkXaQzs');


  print(PublicKey(
          BigInt.tryParse(
              '92108891948304457725712843772415532106347173564369729809572094165443967697408')!,
          BigInt.tryParse(
              '20421979024184426612673771349904865137495236068953777852198657722914191266581')!)
      .encode());

  print('-------');
  print(xpub.generateChildPublicKey(1).encode());
}
