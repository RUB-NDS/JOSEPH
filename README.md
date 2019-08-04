# JOSEPH
![licence](https://img.shields.io/badge/License-GPLv2-brightgreen.svg)
[![release](https://img.shields.io/badge/Release-v1.0.2-blue.svg)](https://github.com/RUB-NDS/JOSEPH/releases)
![status](https://img.shields.io/badge/Status-beta-yellow.svg)
[![travis](https://travis-ci.org/RUB-NDS/JOSEPH.svg?branch=master)](https://travis-ci.org/RUB-NDS/JOSEPH)

## JavaScript Object Signing and Encryption Pentesting Helper

JOSEPH is a Burp Suite extension and has been developed as part of a master thesis by [Dennis Detering](https://github.com/merenon) at the [Ruhr-University Bochum](http://rub.de) in cooperation with the [Spike Reply GmbH](https://reply.de) (formerly [CSPi GmbH](https://www.cspi.com/)).

## Features
- Recognition and marking
- JWS/JWE editors
- (Semi-)Automated attacks
    * Bleichenbacher MMA
    * Invalid Curve
    * Key Confusion (aka Algorithm Substitution)
    * Signature Exclusion
- Base64url en-/decoder
- Easy extensibility of new attacks

## Burp Suite BApp Store
This Burp Suite extension can be downloaded directly from the BApp Store [JSON Web Token Attacker](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61)

## Build
To compile the JOSEPH extension from source, it is necessary to have Apache Maven installed and to run the following command:
```bash
$ mvn clean package
```

To skip the (unit) tests, use the following command:
```bash
$ mvn clean package -DskipTests
```

### Troubleshooting

If the _Oracle JDK_ is installed, the used Bouncy Castle JCE provider dependency is not allowed to be loaded from within a newly compiled fat-JAR, as it breaks the needed signature integrity check.

When performing the Bleichenbacher attack without Bouncy Castle being correctly loaded, the following error will occur:
```
[BleichenbacherPkcs1Info]: Error during key encryption: Cannot find any provider supporting RSA/NONE/NoPadding
```

If this issue arises, please perform the following step(s):

- Copy the Bouncy Castle JAR-file `bcprov-jdk15on-1.54.jar` from JOSEPH's `lib` folder into the `/[PATH_TO_JVM]/jre/lib/ext` directory.

- In some cases, it is necessary to additionally amend the `/[PATH_TO_JVM]/jre/lib/security/java.security` file and add the following line (preferably directly below the other provider definitions): `security.provider.9=org.bouncycastle.jce.provider.BouncyCastleProvider`. The `9` in this case specifies the priority and should be adjusted to fit into existing definitions.


Alternatively, use `target/JOSEPH-1.0.2.jar` and load the `target/lib` folder to your Java Environment under `Extender/Options`.
