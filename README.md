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
This implementation generates artificial key aliases on loading a keystore.
For private key entries with associated certificate chains, the end entity's certificate subject DN in its RFC 2253 format is used as alias name of the entry.

## Resttrictions

### Only AES Encrypted Private Keys

For encrypted private keys, only AES password based encryption is supported. 
3-DES is unsupported due to lacking support in `EncryptedPrivateKeyInfo` of OpenJDK.

If you get an exception of this style on loading a private key, the key might be encrypted with some other algorithm than AES:

```
java.io.IOException: error loading key
 at dev.scheibelhofer.crypto.provider.PemKeystore.engineLoad(PemKeystore.java:205)
 at java.base/java.security.KeyStore.load(KeyStore.java:1473)
...
Caused by: dev.scheibelhofer.crypto.provider.PemKeystoreException: failed decoding encrypted private key
 at dev.scheibelhofer.crypto.provider.Pem$EncryptedPrivateKeyEntry.initFromEncoding(Pem.java:103)
 at dev.scheibelhofer.crypto.provider.PemReader.readEntry(PemReader.java:58)
 at dev.scheibelhofer.crypto.provider.PemReader.readEntries(PemReader.java:28)
 at dev.scheibelhofer.crypto.provider.PemKeystore.engineLoad(PemKeystore.java:174)
 ... 73 more
Caused by: java.io.IOException: PBE parameter parsing error: expecting the object identifier for AES cipher
 at java.base/com.sun.crypto.provider.PBES2Parameters.parseES(PBES2Parameters.java:334)
 at java.base/com.sun.crypto.provider.PBES2Parameters.engineInit(PBES2Parameters.java:238)
 at java.base/java.security.AlgorithmParameters.init(AlgorithmParameters.java:311)
 at java.base/sun.security.x509.AlgorithmId.decodeParams(AlgorithmId.java:147)
 at java.base/sun.security.x509.AlgorithmId.(AlgorithmId.java:129)
 at java.base/sun.security.x509.AlgorithmId.parse(AlgorithmId.java:435)
 at java.base/javax.crypto.EncryptedPrivateKeyInfo.(EncryptedPrivateKeyInfo.java:101)
 at dev.scheibelhofer.crypto.provider.Pem$EncryptedPrivateKeyEntry.initFromEncoding(Pem.java:101)
 ... 76 more
```

Old versions of openssl may used `des3` as default cipher for encrypting private keys.
Even new version can use `des3` if specified explicitely, e.g.:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private-key-des3.pem -pass pass:password -des3
```

As a workaround, you may reencrypt the private key with AES like this:

```
openssl pkey -in private-key-des3.pem -passin pass:password -out private-key-aes128.pem -passout pass:password -aes128
```

The `pem` keystore can load the converted `private-key-aes128.pem` encrypted with `aes128` and password `password`.

### Read-Only Methods

Only read methods of `KeyStore` are supported. Setting entries is unsupported.
