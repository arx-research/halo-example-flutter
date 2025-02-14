import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:esc_pos_utils_plus/dart_hex/hex.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';
import 'package:web3dart/crypto.dart';

import 'eth_utils.dart';


Future<void> selectHaloCore() async {
  String result1 = await FlutterNfcKit.transceive("00A4040007481199130E9F0100");

  if (result1 != "9000") {
    throw "Failed to select HaLo Core application!";
  }
}

typedef GetKeyInfoResult = ({
// reference on key flags:
// https://github.com/arx-research/libhalo/blob/master/core/src.ts/halo/keyflags.ts
int keyFlags,
int failedPwdAttempts,
String publicKeyHex,
String publicKeyAttestSigDERHex,
String address,
});

Future<GetKeyInfoResult> getKeyInfo(keySlotNo) async {
  Uint8List getKeyInfoCmd = Uint8List.fromList([
    0xB0, 0x51, 0x00, 0x00, // CLA, INS, P1, P2
    0x02, // Lc
    0x13, // SHARED_CMD_GET_KEY_INFO
    keySlotNo,
    0x00 // Le
  ]);

  // ---
  // Execute the command on HaLo
  // ---
  List<int> getKeyInfoRes = await FlutterNfcKit.transceive(getKeyInfoCmd);

  if (getKeyInfoRes.length <= 4) {
    throw 'Command error occurred when getting key info: ${HexEncoder().convert(getKeyInfoRes)}';
  }

  int keyFlags = getKeyInfoRes[1];
  int failedPwdAttempts = getKeyInfoRes[2];
  String publicKeyHex = HexEncoder().convert(getKeyInfoRes.sublist(3, 3+65));
  String address = publicKeyToChecksumAddress(publicKeyHex);

  int retAttLen = getKeyInfoRes[3+65+1] + 2;
  String publicKeyAttestSigDERHex = HexEncoder().convert(getKeyInfoRes.sublist(3+65, 3+65+retAttLen));

  return (
  keyFlags: keyFlags,
  failedPwdAttempts: failedPwdAttempts,
  publicKeyHex: publicKeyHex,
  publicKeyAttestSigDERHex: publicKeyAttestSigDERHex,
  address: address,
  );
}

Future<(int, String)?> getPK9PK8Address() async {
  // example of GET_DATA_STRUCT HaLo command for complex logic

  // this function tries to fetch public keys #9 and #8 from HaLo
  // if pk#9 exists, returns ethereum address corresponding to it
  // else if pk#8 exists, returns ethereum address corresponding to it
  // else returns null

  Uint8List getDataStructCmd = Uint8List.fromList([
    0xB0, 0x51, 0x00, 0x00, // CLA, INS, P1, P2
    0x05, // Lc
    0x14, // SHARED_CMD_GET_DATA_STRUCT
    // request structure:
    0x01, 0x09, // Fetch public key #9
    0x01, 0x08, // Fetch public key #8
    0x00 // Le
  ]);

  List<int> getDataStructRes = await FlutterNfcKit.transceive(getDataStructCmd);

  if (getDataStructRes[0] != 0xFF) {
    // public key #9 exists and was returned
    int len = getDataStructRes[0];
    String publicKeyHex = bytesToHex(getDataStructRes.sublist(1, 1+len));
    String address = publicKeyToChecksumAddress(publicKeyHex);
    return (0x09, address);
  }

  getDataStructRes = getDataStructRes.sublist(2);

  if (getDataStructRes[0] != 0xFF) {
    // public key #8 exists and was returned
    int len = getDataStructRes[0];
    String publicKeyHex = bytesToHex(getDataStructRes.sublist(1, 1+len));
    String address = publicKeyToChecksumAddress(publicKeyHex);
    return (0x08, address);
  }

  return null;
}

typedef SignResult = ({
String ethSignature,
String address,
});

Future<SignResult> signWithPassword(keySlotNo, passwordStr, digestStr) async {
  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha512(),
    iterations: 5000, // 5k iterations
    bits: 128, // 128 bits = 16 bytes output
  );

  final derivedPwdHash = await pbkdf2.deriveKeyFromPassword(
    password: passwordStr,
    nonce: utf8.encode('HaLoChipSalt'),
  );

  final pwdHashBytes = await derivedPwdHash.extractBytes();

  List<int> digestBytes = HexDecoder().convert(digestStr);
  List<int> signAuthBytes = [
    0x19,
    ...utf8.encode("Password authentication:\n"),
    keySlotNo,
    ...digestBytes,
    ...pwdHashBytes,
  ];

  final signAuthHashBytes = (await Sha256().hash(signAuthBytes)).bytes;

  // ---
  // Assemble the HaLo command to request making a signature
  // ---
  Uint8List signCmd = Uint8List.fromList([
    0xB0, 0x51, 0x00, 0x00, // CLA, INS, P1, P2
    (2 + digestBytes.length + signAuthHashBytes.length), // Lc
    0xA2, // SHARED_CMD_FETCH_SIGN_PWD
    keySlotNo,
    ...digestBytes,
    ...signAuthHashBytes,
    0x00 // Le
  ]);

  // ---
  // Execute the command on HaLo
  // ---
  List<int> signRes = await FlutterNfcKit.transceive(signCmd);

  if (signRes.length <= 4) {
    throw 'Command error occurred when trying to sign: ${HexEncoder().convert(signRes)}';
  }

  // Response structure:
  // [DER-encoded signature - variable number of bytes]
  // [Uncompressed public key - 65 bytes]
  // [DER-encoded public key attest - variable number of bytes]

  int sigLen = signRes[1] + 2;
  int attLen = signRes[sigLen + 65 + 1] + 2;

  List<int> sigDER = signRes.sublist(0, sigLen);
  List<int> pubKey = signRes.sublist(sigLen, sigLen + 65);
  // List<int> attDER = signRes.sublist(sigLen + 65, sigLen + 65 + attLen);

  String sigDERStr = HexEncoder().convert(sigDER);
  String pubKeyStr = HexEncoder().convert(pubKey);
  // String attDERStr = HexEncoder().convert(attDER);

  var sigPoint = derSignatureToPoint(hexToBytes(sigDERStr));
  var ethSignature = getEthereumSignature(sigPoint, hexToBytes(pubKeyStr).sublist(1), hexToBytes(digestStr));
  var address = publicKeyToChecksumAddress(pubKeyStr);

  return (
  ethSignature: ethSignature,
  address: address
  );
}
