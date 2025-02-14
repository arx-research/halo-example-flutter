import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';
import 'package:logging/logging.dart';
import 'package:ndef/ndef.dart' as ndef;

import 'halo.dart';

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
                        const digestStr = "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2";
                        const passwordStr = "111111"; // key slot password

                        // ---
                        // Select HaLo Core applet
                        // ---
                        await selectHaloCore();

                        // ---
                        // Execute get data struct to retrieve PK#9 or PK#8
                        // ---
                        var record = await getPK9PK8Address();

                        if (record == null) {
                          throw 'Neither public key #9 nor public key slots #9 are generated on this HaLo.';
                        }

                        var (keyNo, ethAddress) = record;
                        print("keyNo: ${keyNo}");
                        print("ethAddress: ${ethAddress}");

                        // ---
                        // Assemble the HaLo command to get key information
                        // ---
                        GetKeyInfoResult keyInfo = await getKeyInfo(keyNo);
                        print("key flags: ${keyInfo.keyFlags}");
                        print("failed auth ctr: ${keyInfo.failedPwdAttempts}");
                        print("ethAddress: ${keyInfo.address}");

                        // ---
                        // Create authorization hash using the provided inputs
                        // ---
                        var signRecord = await signWithPassword(keyNo, passwordStr, digestStr);

                        print("ethSignature ${signRecord.ethSignature}");
                        print("ethAddress ${signRecord.address}");

                        setState(() {
                          _result = 'Signature ETH: ${signRecord.ethSignature}\nAddress: ${signRecord.address}\n\n';
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
