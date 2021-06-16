import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:hdwallet/src/util/util.dart';

void main() {
  final xprv = ExtendedPrivateKey.fromHexString(
    '39f329fedba2a68e2a804fcd9aeea4104ace9080212a52ce8b52c1fb89850c72',
    '05aae71d7c080474efaab01fa79e96f4c6cfe243237780b0df4bc36106228e31',
    props: ExtendedKeyProps(
      depth: 1,
      index: BigInt.from(0),
      parentFingerprint: BigInt.parse('018c1259', radix: 16).toBytes(outLen: 4),
    ),
  );
  print(xprv.serialize());
}
