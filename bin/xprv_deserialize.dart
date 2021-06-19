import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:ninja/ninja.dart';

void main() {
  // Expected
  {
    final xprvStr =
        'xprv9tzRNW1ZnrURDnTFnvwECWXtjDBmUC1SoEwCqnYsoZTUHWpeWPRWhYXkGApgPrQBYZpE31yx89iwMBrKJ8ihEdcpSwRPNcPrdxuzCZ7Fwek';
    final xprv = ExtendedPrivateKey.deserialize(xprvStr);
    print(xprv.privateKey.toRadixString(16));
    print(bytesToBigInt(xprv.chainCode).toRadixString(16));
    print(xprv.props);
  }

  // Actual
  {
    final xprvStr =
        'xprv9tzRNW1ZnrURDnTFnvwECWXtjDBmUC1SoEwCqnYsoZTUHWpeWPRWhYXkGApgPrQBYZpE31yx89iwMBrKJ8ihEdcpSwRPNcPrdxuzCZ7Fwek';
    final xprv = ExtendedPrivateKey.deserialize(xprvStr);
    print(xprv.privateKey.toRadixString(16));
    print(bytesToBigInt(xprv.chainCode).toRadixString(16));
    print(xprv.props);
  }
}
