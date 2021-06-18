import 'package:hdwallet/src/bip32/bip32.dart';
import 'package:test/test.dart';
import 'package:hdwallet/src/util/util.dart';

class _TestCase {
  /// WIF to hex: https://privatekeys.pw/
  final String private;
  final String chainCode;
  final ExtendedKeyProps props;

  /// http://bip32.org/
  final String xprv;

  _TestCase(
      {required this.private,
      required this.chainCode,
      required this.props,
      required this.xprv});

  void execute() {
    // final x = ExtendedPrivateKey.deserialize(xprv);
    // print(x.privateKey.toRadixString(16));

    final key = ExtendedPrivateKey.fromHexString(
      private,
      chainCode,
      props: props,
    );

    final serialized = key.serialize();
    expect(serialized, xprv);

    final xprvDeserialized = ExtendedPrivateKey.deserialize(serialized);
    expect(xprvDeserialized.privateKey.toRadixString(16), private);
    expect(xprvDeserialized.chainCode.toHex(), chainCode);
    expect(xprvDeserialized.props!.index, props.index);
    expect(xprvDeserialized.props!.depth, props.depth);
    expect(xprvDeserialized.props!.parentFingerprint, props.parentFingerprint);
  }
}

void main() {
  test('xprv.serialize', () {
    var tc = _TestCase(
        private:
            '39f329fedba2a68e2a804fcd9aeea4104ace9080212a52ce8b52c1fb89850c72',
        chainCode:
            '05aae71d7c080474efaab01fa79e96f4c6cfe243237780b0df4bc36106228e31',
        props: ExtendedKeyProps(
          depth: 1,
          index: 0,
          parentFingerprint:
              BigInt.parse('018c1259', radix: 16).toBytes(outLen: 4),
        ),
        xprv:
            'xprv9tuogRdb5YTgcL3P8Waj7REqDuQx4sXcodQaWTtEVFEp6yRKh1CjrWfXChnhgHeLDuXxo2auDZegMiVMGGxwxcrb2PmiGyCngLxvLeGsZRq');
    tc.execute();

    tc = _TestCase(
        private:
            '99ae6cfc5891524f985b8af304019156d5452e56144e71bec32b4017e245e9a9',
        chainCode:
            '9a7f6ab773e03bd5c83a9581c063ed0b3df094abe5fe103099c4b001d2424d48',
        props: ExtendedKeyProps(
            depth: 5,
            parentFingerprint:
                BigInt.parse('d9d54e0d', radix: 16).toBytes(outLen: 4),
            index: 100),
        xprv:
            'xprvA42Z1G1J8scF17SNMaLLdSDw5bT4teyahaAQpaumr97ci1e49XHbXfKVbpJP3BHCq3oro9E4h7nHiXk1wybHFreKeGysV4E9npZ3joaumqi');
    tc.execute();
  });
}
