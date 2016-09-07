# Nodes

Nodes in Neo4J for the MobileSandbox are:

* `Android` - An Android Application, create with `create_node`
* `Certificate` - A Certificate used for an Android Application
* `PublicKey` - A Public Key that is used in a Certificate to verify signatures
* `File` - A file inside an unzipped Android Application
* `DEX_File` - A file inside the `classes.dex`
* `Activity` - An activity found inside the AndroidManifest.xml / used in the application
* `Intent` - An Intent requested for an application
* `Provider` - A provider found inside the AndroidManifest.xml / used in the application
* `Service_Receiver` - A service or receiver found inside the AndroidManifest.xml / used in the application
* `Feature` - A feature found inside the AndroidManifest.xml / used in the application
* `Package_Name` - The package name of an application
* `App_Name` - The name of an application as displayed in the market
* `SDK_Version_Target` - The target SDK version of an application
* `SDK_Version_Min` - The minimal SDK version required to use the application
* `SDK_Version_Max` - The maximal SDK version required to use the application
* `API_Call` - A procedure call that occurred during dynamic analysis
* `Permission` - A permission requested in the AndroidManifest.xml or used during dynamic analysis
* `Antivirus` - A malware name given by any Antivirus engine

Nodes that still need work:

* `Networks` - A network TODO
* `Detected_Ad_Networks` - A detected Ad network TODO
* `URL` - An URL detected in the strings dump of an application TODO

Future nodes:

* `Host` - A hostname / IP (un-)successfully contacted during a network operation
* `Phone` - A phone number contacted during a network operation
* `Crypto` - A crypto operation

# Relationships

Relationships that can bind nodes together are:

* `SIGNED_WITH` - Android Applications that are signed with a particular Certificate
* `AUTHENTICATED_BY` - Certificates which signatures are authenticated by a particular PublicKey
* `HAS_FILE` - Android Applications that contain a particular file
* `HTTP_TRAFFIC` - URLs requested and data sent by Android Applications
* `RESOLVES_TO` - Hostnames that resolve to IPs
* `SEND_SMS` - Android Applications that send SMS to a Host
* `NETWORK_LEAK` - Android Applications that send private data to a Host
* `APPLIES_CRYPTO` - Android Applications that apply crypto operations to e.g. decrypt configuration files
