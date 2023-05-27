# java-crypto-tools

[![Maven Central](https://img.shields.io/maven-central/v/dev.scheibelhofer/crypto-tools)](https://central.sonatype.com/artifact/dev.scheibelhofer/crypto-tools/)

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
The format of the entries are specified in [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468).

## Usage

Include the maven dependency in your `pom-xml`:

```xml
<dependency>
  <groupId>dev.scheibelhofer</groupId>
  <artifactId>crypto-tools</artifactId>
  <version>0.0.1</version>
</dependency>
```

If you have private key and certificates in OpenSSL PEM format in separate files, 
simply write them all together in a single file. 
For example:

```bash
cat private-key.pem webserver-certificate.crt intermediate-ca-certificate.crt root-ca-certificate.crt > webserver-key-and-certificate-chain.pem
```

Typical usage:

```java
import dev.scheibelhofer.crypto.provider.JctProvider;

KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
ks.load(new FileInputStream("webserver-key-and-certificate-chain.pem"), password);
```

Note that there is no need to install the `JctProvider` using `java.security.Security#addProvider(Provider)` or `java.security.Security#insertProviderAt(Provider,int)`. 
This eliminates the risk that this provicer interferes with existing ones.

## Creating OpenSSL Keystores

If you are familiar with OpenSSL keys and certificates, there is nothing new in this section.

An OpenSSL keystore is jsut a plain text file, typically containing private key and certificates that comprise the certificate chain for the key.
The private key can be unencrypte or encrypted based on a password.
For encrypted private keys ensure that AES is used, e.g. using the `-aes128` option for OpenSSL.

Special lines delimit the entries a such a keystore. 
These boundary lines begin with `-----BEGIN` before an entry and with `-----BEGIN` ending an entry.
In between these lines, there is [base-64](https://www.rfc-editor.org/rfc/rfc7468) encoded content of keys or certificates.

This is the complete content of a valid PEM keystore file:

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgC6Z/5UQUayiATltT
gKqSGjfCslChP848q5K1kfho4J+hRANCAASSUlsdE9CoWwHcbrpqrU0DOOeKtWhW
FUq6t+5zuLPZV8htXQnhHDa7l82/ab4rbjlaRUPaj0MMqjbd/DzKJWNF
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIBujCCAV+gAwIBAgIUbwte5FfGHJEQ2iNjv7/Tu4btJe4wCgYIKoZIzj0EAwIw
LzELMAkGA1UEBhMCQVQxIDAeBgNVBAMMF1Rlc3QtSW50ZXJtZWRpYXRlLUNBLUVD
MB4XDTIzMDQwODE2NDIyOFoXDTI0MDQwODE2NDIyOFowIjEgMB4GA1UEAwwXd3d3
LmRvZXNub3RleGlzdC5vcmctRUMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASS
UlsdE9CoWwHcbrpqrU0DOOeKtWhWFUq6t+5zuLPZV8htXQnhHDa7l82/ab4rbjla
RUPaj0MMqjbd/DzKJWNFo2YwZDAiBgNVHREEGzAZghd3d3cuZG9lc25vdGV4aXN0
Lm9yZy1FQzAdBgNVHQ4EFgQUybzeSXjHALSgPGI5BoueKoFwhtEwHwYDVR0jBBgw
FoAUiekAtyaWnn8FUz+NbGBwg/hRu1cwCgYIKoZIzj0EAwIDSQAwRgIhAK3vGNB4
F1YHRvBX+/NWF+g+TtzcFceuOVXJxvGhzmDmAiEA8QXltXLHpTP5JGz4jX06DWDj
P7d4F6WeChLwcnJoTv0=
-----END CERTIFICATE-----
```

To create a new EC P-256 key and protecting the private key using the password `topsecret` use somethins like this:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out webserver-private-key.pem -pass pass:topsecret -aes128
```

To generate a self-signed certficiate, which is sufficent for simple tests, you can use:

```bash
openssl req -x509 -new -key webserver-private-key.pem -passin pass:topsecret -addext subjectAltName=DNS:www.doesnotexist.org -addext "basicConstraints= critical, CA:false" -out webserver-certificate.pem -sha256 -days 3650 -subj "/CN=www.doesnotexist.org"
```

Then, you can create a PEM keystore including the private key and the certificate by simply concatenating them:

```bash
cat webserver-private-key.pem webserver-certificate.pem > webserver-keystore.pem
```

```java
import dev.scheibelhofer.crypto.provider.JctProvider;

char[] password = "topsecret".toCharArray();
KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
ks.load(new FileInputStream("webserver-keystore.pem"), password);
```

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

### Setting Keys and Storing

Only basic setting of an unencrypted private key with certificate chain and setting trusted certificate entries is supported. 

For example:

```java
KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
ks.load(null, null);

PrivateKey privateKey = ...;
X509Certificate certificate = ...;
X509Certificate caCertificate = ...;
X509Certificate rootCertificate = ...;

Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate};
ks.setKeyEntry(alias, privateKey, null, certChain);

File keystoreFile = ...;
char[] password = ...;
try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
    ks.store(fos, password.toCharArray());    
}
```

### Unsupported Methods

The following `java.security.KeyStore` Methods are unsupported:

* `setKeyEntry(String alias, byte[] key, Certificate[] chain)`
  * setting an encrypted key entry
  * https://github.com/KarlScheibelhofer/java-crypto-tools/issues/6 
* `getCertificateAlias(Certificate cert)`
  * getting the alias of a certificate entry
  * https://github.com/KarlScheibelhofer/java-crypto-tools/issues/4
