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

Typical useage:

```java
import dev.scheibelhofer.crypto.provider.CryptoSupportProvider;

KeyStore ks = KeyStore.getInstance(keyStoreType, CryptoSupportProvider.getInstance());
        
```

Note that there is no need to install the `CryptoSupportProvider`. 
This eliminates the risk that this provicer intereferres with existing ones.

## Resttrictions

* For encrypted private keys, only AES password based encryption is supported. 
3-DES is unsupported due to lacking support in `EncryptedPrivateKeyInfo` of OpenJDK.
* Only read methods of `KeyStore` are supported. Setting entries or saving are unsupported.
