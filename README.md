# flutter_halo_poc

A simple Flutter demo app (based on flutter_nfc_kit's demo app) that demonstrates how to
retrieve HaLo tag's key information or request creating a signature for a chosen digest.

The required adjustments on the native iOS/Android side:

* iOS Info.plist: NFCReaderUsageDescription
* iOS Info.plist: com.apple.developer.nfc.readersession.iso7816.select-identifiers for the following identifiers:
  * `481199130E9F01` (required)
  * `D2760000850101` (optional)
  * `A0000006472F0001` (optional)
* iOS Entitlements: NFC entitlement
* AndroidManifest.xml: NFC permission

More about those is described in flutter_nfc_kit documentation.
