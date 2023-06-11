# java-crypto-tools

[![Maven Central](https://img.shields.io/maven-central/v/dev.scheibelhofer/crypto-tools)](https://central.sonatype.com/artifact/dev.scheibelhofer/crypto-tools/)

This library enables reading and writing keys and certificate in Java via the JCA KeyStore API.
It includes a JCA provider implementing a `pem` type `KeyStore`. 
It allows reading and writing unencrypted or encrypted  private keys and certificates.

It enables easy integration of PEM keystores like the PEM version of the Common CA Database from Mozilla.

Many software products use PEM (see [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468)) as format for cryptographic keys and certificates.
PEM format, as known in OpenSSL and many system based on it, is one of the most versatile formats for this type of data.
If you get keys or certificates, it is most likely that you get it in PEM.
To use it in Java, you typically had to import it in a Java keystore of type JKS or PKCS12.
With this library, this conversion is no longer required.
You can read and write PEM files directly without the need for conversion.

Requirements:
* Java 11 or higher

## Features

The `pem` keystore reads a file containing multiple PEM entries of these types:

* X.509 Certificates
* Private Keys
* Encrypted Private Keys (AES encryption)
 
Features:

* Supports RSA and EC keys

The keystore file can contain multiple entries.
The format of the entries are specified in [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468).

The `pem-directory` keystore ready all files in a directory tree.

## Include

Include the maven dependency in your `pom-xml`:

```xml
<dependency>
  <groupId>dev.scheibelhofer</groupId>
  <artifactId>crypto-tools</artifactId>
  <version>0.0.5</version>
</dependency>
```

### PEM File

If you have private key and certificates in OpenSSL PEM format in separate files, 
simply write them all together in a single file. 
For example:

```bash
cat private-key.pem webserver-certificate.crt intermediate-ca-certificate.crt root-ca-certificate.crt > webserver-key-and-certificate-chain.pem
```

#### Reading PEM Files

Here is a typical piece of Java code using this keystore:

```java
import dev.scheibelhofer.crypto.provider.JctProvider;

KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
ks.load(new FileInputStream("webserver-key-and-certificate-chain.pem"), password);
```

Note that there is no need to install the `JctProvider` using `java.security.Security#addProvider(Provider)` or `java.security.Security#insertProviderAt(Provider,int)`. 
This eliminates the risk that this provider interferes with existing ones.

To import the [Common CA Database file](https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites) write something like:

```java
import dev.scheibelhofer.crypto.provider.JctProvider;

KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
ks.load(new FileInputStream("IncludedRootsPEM.txt"), null);
```

Note that the password can be `null` because there is not encryption or MAC protection in PEM certificate files.

#### Writing PEM Files

Setting a private key with certificate chain and setting trusted certificate entries is supported. 

To set a private key with certificate chain, look at this example:

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

#### Aliases

The PEM format usually does not contain names for its entries.
Thus, this implementation usually generates artificial key aliases on loading a keystore.
For private key entries with associated certificate chains, the end entity's certificate subject DN in its RFC 2253 format is used as alias name of the entry.

This implementation, however, supports setting special `Explanatory Text` lines with label `Alias:` before each keystore entry. 
If there is such a line, its value is used as the alias of the following entry.

Such an entry will look something like this:

```
Alias: www.doesnotexist.org
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgC6Z/5UQUayiATltT
gKqSGjfCslChP848q5K1kfho4J+hRANCAASSUlsdE9CoWwHcbrpqrU0DOOeKtWhW
FUq6t+5zuLPZV8htXQnhHDa7l82/ab4rbjlaRUPaj0MMqjbd/DzKJWNF
-----END PRIVATE KEY-----
```

For private key entries with a certificate chain, it is sufficient, if the key has an alias. 

A line with `Alias: ` is also created when writing a keystore created in Java.

### PEM Directory Tree

The `pem-directory` KeyStore implementation supports reading all PEM files in a directory tree.

To read all files in a directory tree, you need to supply a stream that contains the file path of the directory. 
This is necessary because the `load` method of a Java KeyStore only accepts an InputStream as source.

#### Reading PEM Directory

Here is an example:

```java
import dev.scheibelhofer.crypto.provider.JctProvider;

KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

try (InputStream is = new ByteArrayInputStream("src/test/resources/ca-certificates".getBytes(StandardCharsets.UTF_8))) {
    ks.load(is, null);
}
```

This will load all files in the directory `src/test/resources/ca-certificates`.

#### Writing PEM Directory

Writing a `pem-directory` needs a different flow, because the `store` method of KeyStore takes an `OutputStream`.
This does not easily allow to write multiple files to a directory.
Thus, the application must load the `pem-directory` just as in reading an existing one.
The provided directory name, however, does not need to exist.
The implementation gets the directory name via the `InputStream` 
and is uses this directory to store the PEM files to during the subsequent call to the KeyStore's `store` method.

Have a look at this example which creates new PEM directory keystore in `src/test/resources/out/truststore-dir`:

```java
import dev.scheibelhofer.crypto.provider.JctProvider;

KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

// just a pseudo keystore file containing the name of our PEM directory
Path pemKeystoreDirFile = Paths.get("src/test/resources/out/truststore.pem-directory");
Files.writeString(pemKeystoreDirFile, Paths.get("src/test/resources/out/truststore-dir").toFile().getAbsolutePath(), StandardCharsets.UTF_8);

// load this diretory name into the keystore via a call to load
try (FileInputStream is = new FileInputStream(pemKeystoreDirFile.toFile())) {
    ks.load(is, null);
}

// store your entries in the keystore
X509Certificate caCertificate1 = ...;
X509Certificate caCertificate2 = ...;

ks.setCertificateEntry("ca-certificate-1", caCertificate1);
ks.setCertificateEntry("ca-certificate-2", caCertificate2);

// now store the entries to the directory provided before via the call to load()
// no output stream needed, if supplied, it is just closed
ks.store(null, null);
```

Each entry is stored in a separate PEM file, in this example in `src/test/resources/out/truststore-dir`.

#### Aliases

The `pem-directory` KeyStore uses the filenames as alias of the entries.

## Creating OpenSSL Keystores

If you are familiar with OpenSSL keys and certificates, there is nothing new in this section.

An OpenSSL keystore is just a plain text file, typically containing private key and certificates that comprise the certificate chain for the key.
The private key can be unencrypted or encrypted based on a password.
For encrypted private keys ensure that AES is used, e.g. using the `-aes128` option for OpenSSL.

Special lines delimit the entries in such a keystore. 
These boundary lines start with `-----BEGIN` before an entry and with `-----BEGIN` ending an entry.
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

To create a new EC P-256 key and protecting the private key using the password `topsecret` use something like this:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out webserver-private-key.pem -pass pass:topsecret -aes128
```

To generate a self-signed certificate, which is sufficient for simple tests, you can use:

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

## Restrictions

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

Old versions of openssl may use `des3` as default cipher for encrypting private keys.
Even new version can use `des3` if specified explicitely, e.g.:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private-key-des3.pem -pass pass:password -des3
```

As a workaround, you may re-encrypt the private key with AES like this:

```
openssl pkey -in private-key-des3.pem -passin pass:password -out private-key-aes128.pem -passout pass:password -aes128
```

The `pem` keystore can load the converted `private-key-aes128.pem` encrypted with `aes128` and password `password`.
