package dev.scheibelhofer.crypto.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Internal support class for reading and writing PEM format keys and certificates.
 */
class Pem {

    static abstract class Entry {
        static enum Type {
            privateKey, certificate, encryptedPrivateKey, unknown
        }

        Type type;
        byte[] encoding;
        String alias;

        Entry(Type type, String alias) {
            this.type = type;
            this.alias = alias;
        }

        void initFromEncoding(byte[] encoding) {
            this.encoding = encoding;
        }
        
    }
    
    static class PrivateKeyEntry extends Entry {
        PrivateKey privateKey;
        
        PrivateKeyEntry(String alias) {
            super(Type.privateKey, alias);
        }
        
        PrivateKeyEntry(Type type, String alias) {
            super(type, alias);
        }
        
        PrivateKeyEntry(String alias, PrivateKey privateKey) {
            this(alias);
            this.privateKey = privateKey;
            this.encoding = privateKey.getEncoded();
        }

        @Override
        void initFromEncoding(byte[] encoding) {
            super.initFromEncoding(encoding);
            try {
                PKCS8EncodedKeySpec spec = createPkcs8KeySpec(encoding);
                KeyFactory kf = KeyFactory.getInstance(spec.getAlgorithm());
                this.privateKey = kf.generatePrivate(spec);
            } catch (Exception e) {
                throw new PemKeystoreException("failed decoding private key entry", e);
            }
        }       
        
        private static PKCS8EncodedKeySpec createPkcs8KeySpec(byte[] encoding) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException {
            // we must tweak around a litte to access the PKCS#8 decoding feature only available in EncryptedPrivateKeyInfo
            AlgorithmParameters nullAlgorithmParam = AlgorithmParameters.getInstance("0.1", JctProvider.getInstance());
            EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(nullAlgorithmParam, encoding);
            Cipher nullCipher = Cipher.getInstance("null", JctProvider.getInstance());
            nullCipher.init(Cipher.DECRYPT_MODE, new NullPrivateKey());
            return epki.getKeySpec(nullCipher);
        }
                
    }
    
    static class EncryptedPrivateKeyEntry extends PrivateKeyEntry {
        EncryptedPrivateKeyInfo encryptedPrivateKey;

        EncryptedPrivateKeyEntry(String alias) {
            super(Type.encryptedPrivateKey, alias);
        }

        @Override
        void initFromEncoding(byte[] encoding) {
            this.encoding = encoding;
            try {
                this.encryptedPrivateKey = new EncryptedPrivateKeyInfo(encoding);
            } catch (IOException e) {
                throw new PemKeystoreException("failed decoding encrypted private key", e);
            }
        }
        
        void decryptPrivateKey(char[] password) throws NoSuchAlgorithmException {
            try {
                PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
                AlgorithmParameters algParams = this.encryptedPrivateKey.getAlgParameters();
                // toString() yields the correct name for the cipher, not epki.getAlgName();
                String pbes2Name = algParams.toString();
                SecretKeyFactory skf = SecretKeyFactory.getInstance(pbes2Name);
                Key pbeKey = skf.generateSecret(pbeKeySpec);
                Cipher cipher = Cipher.getInstance(pbes2Name);
                cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
                PKCS8EncodedKeySpec keySpec = this.encryptedPrivateKey.getKeySpec(cipher);
                KeyFactory kf = KeyFactory.getInstance(keySpec.getAlgorithm());
                this.privateKey = kf.generatePrivate(keySpec);
            } catch (Exception e) {
                throw new PemKeystoreException("error decrypting private key", e);
            }
        }        
    }
    
    static class CertificateEntry extends Entry {
        X509Certificate certificate;
        
        CertificateEntry(String alias) {
            super(Type.certificate, alias);
        }
        
        CertificateEntry(String alias, X509Certificate certificate) {
            this(alias);
            this.certificate = certificate;
            try {
                this.encoding = certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                throw new PemKeystoreException("failed encoding certificate", e);
            }
        }
        
        @Override
        void initFromEncoding(byte[] encoding) {
            super.initFromEncoding(encoding);
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");         
                this.certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoding));
            } catch (Exception e) {
                throw new PemKeystoreException("failed decoding certificate", e);
            }
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((certificate == null) ? 0 : certificate.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            CertificateEntry other = (CertificateEntry) obj;
            if (certificate == null) {
                if (other.certificate != null)
                    return false;
            } else if (!certificate.equals(other.certificate))
                return false;
            return true;
        }
        
    }
    
    static class UnknownEntry extends Entry {
        String pemBeginLine;
        
        UnknownEntry(String alias, String pemBeginLine) {
            super(Type.unknown, alias);
            this.pemBeginLine = pemBeginLine;
        }
    }        

    final static String BEGIN = "-----BEGIN";
    final static String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    final static String END_CERTIFICATE = "-----END CERTIFICATE-----";
    final static String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    final static String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    final static String BEGIN_ENCRYPTED_PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    final static String END_ENCRYPTED_PRIVATE_KEY = "-----END ENCRYPTED PRIVATE KEY-----";
    final static String END = "-----END";

}
