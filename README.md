# java-crypto-tools

This library includes a JCA provider implementing a `PemKeyStore` for the JCA `KeyStore` API. 
It allows reading (plain) private keys, certificates and encrypted private keys.

Requirements:
* Java 11 or higher

## Features

The `PemKeyStore` reads a file containing multiple PEM entries of these types:

* X.509 Certificates
* Private Keys
* Encrypted Private Keys (AES encryption)
 
Features:

* Supports RSA and EC keys

The keystore file can contain multiple entries.
The format of the entries are specified in https://www.rfc-editor.org/rfc/rfc7468.

## Usage

Include the maven dependency in your `pom-xml`:

```xml
<dependency>
  <groupId>dev.scheibelhofer</groupId>
  <artifactId>crypto-tools</artifactId>
  <version>0.0.1</version>
</dependency>
```

Typical usage:

```java
import dev.scheibelhofer.crypto.provider.CryptoSupportProvider;

KeyStore ks = KeyStore.getInstance("pem", CryptoSupportProvider.getInstance());
ks.load(new FileInputStream("key-and-certificate.pem"), password);
```

Note that there is no need to install the `CryptoSupportProvider` using `java.security.Security#addProvider(Provider)` or `java.security.Security#insertProviderAt(Provider,int)`. 
This eliminates the risk that this provicer intereferres with existing ones.

## Aliases

The PEM format usualy does not contain names for its entries.
This implementation generated key aliases on loading a keystore.
For private key entries with associated certificate chains, the end entity's certificate subject DN in its RFC 2253 format is used as alias name of the entry.

## Resttrictions

* For encrypted private keys, only AES password based encryption is supported. 
  3-DES is unsupported due to lacking support in `EncryptedPrivateKeyInfo` of OpenJDK.
* Only read methods of `KeyStore` are supported. Setting entries or saving are unsupported.
