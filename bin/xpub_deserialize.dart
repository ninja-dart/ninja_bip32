import 'package:ninja_bip32/src/bip32/bip32.dart';

void main() {
  {
    final xpubStr =
        'xpub67ymn1YTdE2iSGXitxUEZeUdHF2FsejJATroeAxVMtzTAK9o3vjmFLrE7TqE1X76iobkVc3p8h3gNzNRTwPeQGYW3CCmYCG8n5ThVkXaQzs';
    final xpub = ExtendedPublicKey.deserialize(xpubStr);
    print(xpub.encode());
    print(xpub.chainCodeHex);
    print(xpub.props);
  }
}
