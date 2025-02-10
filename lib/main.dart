import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform, sleep;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';
import 'package:logging/logging.dart';
import 'package:ndef/ndef.dart' as ndef;
import 'package:ndef/utilities.dart';
import 'package:cryptography/cryptography.dart';
import 'package:esc_pos_utils_plus/dart_hex/hex.dart';

import 'ndef_record/raw_record_setting.dart';
import 'ndef_record/text_record_setting.dart';
import 'ndef_record/uri_record_setting.dart';

void main() {
  Logger.root.level = Level.ALL; // defaults to Level.INFO
  Logger.root.onRecord.listen((record) {
    print('${record.level.name}: ${record.time}: ${record.message}');
  });
  runApp(MaterialApp(theme: ThemeData(useMaterial3: true), home: MyApp()));
}

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> with SingleTickerProviderStateMixin {
  String _platformVersion = '';
  NFCAvailability _availability = NFCAvailability.not_supported;
  NFCTag? _tag;
  String? _result, _writeResult, _mifareResult;
  late TabController _tabController;
  List<ndef.NDEFRecord>? _records;

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    if (!kIsWeb)
      _platformVersion =
          '${Platform.operatingSystem} ${Platform.operatingSystemVersion}';
    else
      _platformVersion = 'Web';
    initPlatformState();
    _tabController = new TabController(length: 2, vsync: this);
    _records = [];
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    NFCAvailability availability;
    try {
      availability = await FlutterNfcKit.nfcAvailability;
    } on PlatformException {
      availability = NFCAvailability.not_supported;
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      // _platformVersion = platformVersion;
      _availability = availability;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
            title: const Text('NFC Flutter Kit Example App'),
            bottom: TabBar(
              tabs: <Widget>[
                Tab(text: 'Read'),
              ],
              controller: _tabController,
            )),
        body: new TabBarView(controller: _tabController, children: <Widget>[
          Scrollbar(
              child: SingleChildScrollView(
                  child: Center(
                      child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: <Widget>[
                const SizedBox(height: 20),
                Text('Running on: $_platformVersion\nNFC: $_availability'),
                const SizedBox(height: 10),
                ElevatedButton(
                  onPressed: () async {
                    try {
                      NFCTag tag = await FlutterNfcKit.poll();
                      setState(() {
                        _tag = tag;
                      });
                      await FlutterNfcKit.setIosAlertMessage(
                          "Working on it...");
                      _mifareResult = null;
                      if (tag.standard == "ISO 14443-4 (Type A)") {
                        // ---
                        // Inputs
                        // ---
                        const keySlotNo = 0x08;
                        const digestStr = "0102030405060708090A0B0C0D0E0F010102030405060708090A0B0C0D0E0F01";
                        const passwordStr = "111111"; // key slot password

                        // ---
                        // Select HaLo Core applet
                        // ---
                        String result1 = await FlutterNfcKit.transceive(
                            "00A4040007481199130E9F0100");

                        if (result1 != "9000") {
                          throw "Failed to select HaLo Core app!";
                        }

                        // ---
                        // Assemble the HaLo command to get key information
                        // ---
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
                        String retPubKey = HexEncoder().convert(getKeyInfoRes.sublist(3, 3+65));
                        int retAttLen = getKeyInfoRes[3+65+1] + 2;
                        String retPubKeyAttest = HexEncoder().convert(getKeyInfoRes.sublist(3+65, 3+65+retAttLen));

                        // reference on key flags: https://github.com/arx-research/libhalo/blob/master/core/src.ts/halo/keyflags.ts
                        print("Key flags: ${keyFlags}");
                        print("Failed pwd attempts: ${failedPwdAttempts}");
                        print("Public key: ${retPubKey}");
                        print("Attest: ${retPubKeyAttest}");

                        // ---
                        // Create authorization hash using the provided inputs
                        // ---
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
                        List<int> attDER = signRes.sublist(sigLen + 65, sigLen + 65 + attLen);

                        String sigDERStr = HexEncoder().convert(sigDER);
                        String pubKeyStr = HexEncoder().convert(pubKey);
                        String attDERStr = HexEncoder().convert(attDER);

                        print('Signature DER: ${sigDERStr}');
                        print('Public Key: ${pubKeyStr}');
                        print('Key Attest DER: ${attDERStr}');

                        setState(() {
                          _result = 'Signature DER: ${sigDERStr}\nPublic Key: ${pubKeyStr}\nKey Attest DER: ${attDERStr}\n\n';
                        });
                      } else {
                        throw 'Unsupported tag type: ${tag.standard}';
                      }
                    } catch (e) {
                      setState(() {
                        _result = 'error: $e';
                      });
                    }

                    await FlutterNfcKit.finish(iosAlertMessage: "Finished!");
                  },
                  child: Text('Start polling'),
                ),
                const SizedBox(height: 10),
                Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 20),
                    child: _tag != null
                        ? Text(
                            'ID: ${_tag!.id}\nStandard: ${_tag!.standard}\nType: ${_tag!.type}\nTransceive Result:\n$_result\n\n')
                        : const Text('No tag polled yet.')),
              ])))),
        ]),
      ),
    );
  }
}
