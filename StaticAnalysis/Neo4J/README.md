# Nodes

Nodes in Neo4J for the MobileSandbox are:

* `Android` - An Android Application, create with `create_node`
* `Certificate` - A Certificate used for an Android Application
* `File` - A file inside an unzipped Android Application
* `Host` - A hostname / IP (un-)successfully contacted during a network operation
* `Phone` - A phone number contacted during a network operation
* `Crypto` - A crypto operation

# Relationships

Relationships that can bind nodes together are:

* `SIGNED_WITH` - Android Applications that are signed with a particular Certificate
* `HAS_FILE` - Android Applications that contain a particular file
* `HTTP_TRAFFIC` - URLs requested and data sent by Android Applications
* `RESOLVES_TO` - Hostnames that resolve to IPs
* `SEND_SMS` - Android Applications that send SMS to a Host
* `NETWORK_LEAK` - Android Applications that send private data to a Host
* `APPLIES_CRYPTO` - Android Applications that apply crypto operations to e.g. decrypt configuration files
