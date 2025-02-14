import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:pointycastle/digests/keccak.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:web3dart/crypto.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:sec/sec.dart';

final ECDomainParameters params = ECCurve_secp256k1();
final BigInt _halfCurveOrder = params.n >> 1;

// source: https://gist.github.com/thecipherBlock/c20add0e3ddae576abe847e56d99c9f7
String addressToChecksumAddress(String ethAddress) {
  // Checking for 0x prefix
  String addrWithoutChecksum = ethAddress.substring(0, 2) == '0x'
      ? ethAddress.substring(2, ethAddress.length)
      : ethAddress;

  /// Address should be size 20 bytes ie., 40 hex characters
  if (addrWithoutChecksum.length != 40) {
    throw "invalid ethereum address length";
  }

  addrWithoutChecksum = addrWithoutChecksum.toLowerCase();
  // Hash the address
  final List<int> codeUnits = addrWithoutChecksum.codeUnits;
  final Uint8List unit8List = Uint8List.fromList(codeUnits);
  final KeccakDigest keccakDigest = KeccakDigest(256);
  Uint8List hashedAddr = keccakDigest.process(unit8List);
  String hashedAddrInString = hex.encode(hashedAddr);

  // Generation of checksum
  String addrWithChecksum = "0x";
  for (int j = 0; j < addrWithoutChecksum.length; j++) {
    final int i = int.parse(hashedAddrInString[j], radix: 16);
    if (i > 7) {
      addrWithChecksum += addrWithoutChecksum[j].toUpperCase();
    } else {
      addrWithChecksum += addrWithoutChecksum[j];
    }
  }
  return addrWithChecksum;
}

String publicKeyToChecksumAddress(String publicKeyHex) {
  assert(publicKeyHex.length == 65);
  return addressToChecksumAddress(bytesToHex(
      publicKeyToAddress(hexToBytes(publicKeyHex).sublist(1))
  ));
}

(BigInt, BigInt) derSignatureToPoint(Uint8List derSig) {
  // we only support DER encoded SECp256k1 signature point format
  assert(derSig[0] == 0x30);
  int totalLength = derSig[1];

  assert(derSig[2] == 0x02);
  int rLength = derSig[3];
  BigInt r = BigInt.parse(bytesToHex(derSig.sublist(4, 4+rLength)), radix: 16);

  int sOffset = 4+rLength;
  assert(derSig[sOffset] == 0x02);
  int sLength = derSig[sOffset+1];
  BigInt s = BigInt.parse(bytesToHex(derSig.sublist(sOffset+2, sOffset+2+sLength)), radix: 16);

  assert(totalLength == rLength+sLength+4);
  return (r, s);
}

String getEthereumSignature((BigInt, BigInt) sigPoint, Uint8List publicKey, Uint8List digest) {
  var (r, s) = sigPoint;
  var canonicalisedS = s;

  if (s.compareTo(_halfCurveOrder) > 0) {
    canonicalisedS = params.n - s;
  }

  int? keyId = EC.secp256k1.calculateRecoveryId(
      bytesToUnsignedInt(publicKey),
      ECSignature(r, canonicalisedS),
      digest
  );

  if (keyId == null) {
    throw Exception("Failed to recover public key!");
  }

  return '0x${r.toRadixString(16).padLeft(64, '0')}${canonicalisedS.toRadixString(16).padLeft(64, '0')}${bytesToHex([0x1b + keyId])}';
}
