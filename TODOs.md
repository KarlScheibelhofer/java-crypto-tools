# TODOs

TODOs in this branch:

* Move implementation to sun.secrity.provider.pemkeystore, to be able to use `sun.security.pkcs.PKCS8Key` for decoding private keys
* Remove classes
  * NullAlgorithmParameters
  * NullCipher
  * NullPrivateKey
  * PBES2AlgorithmParameters
* Reduce and refine code in classes
  * Pem
  * PemReader
  * PemWriter