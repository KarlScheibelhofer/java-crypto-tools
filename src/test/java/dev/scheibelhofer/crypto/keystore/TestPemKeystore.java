package dev.scheibelhofer.crypto.keystore;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import dev.scheibelhofer.crypto.provider.CryptoSupportProvider;

public class TestPemKeystore {

    InputStream getResource(String name) {
        return getClass().getClassLoader().getResourceAsStream(name);
    }
    
    X509Certificate getRessourceCertificate(String name) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(getResource(name));
    }

    @Test
    public void testLoadPemTruststore() throws Exception {
        CryptoSupportProvider prov = new CryptoSupportProvider();

        KeyStore ks = KeyStore.getInstance("PemKeyStore", prov);
        Assertions.assertNotNull(ks);
        
        ks.load(getResource("truststore.pem"), null);
        Assertions.assertEquals(4, ks.size());

        Set<Certificate> certSet = new HashSet<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        certSet.add(cf.generateCertificate(getResource("github.com.crt")));
        certSet.add(cf.generateCertificate(getResource("google.com.crt")));
        certSet.add(cf.generateCertificate(getResource("microsoft.com.crt")));
        certSet.add(cf.generateCertificate(getResource("orf.at.crt")));

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (ks.isCertificateEntry(alias)) {
                Certificate c = ks.getCertificate(alias);
                Assertions.assertNotNull(c);
                Assertions.assertTrue(certSet.contains(c));
                if (c instanceof X509Certificate) {
                    X509Certificate xc = (X509Certificate) c;
                    String subjectDN = xc.getSubjectX500Principal().getName();
                    Assertions.assertEquals(subjectDN, alias);
                } else {
                    Assertions.fail();
                }
            } else {
                Assertions.fail();
            }
        }
    }

    public void checkPrivateKey(String keyStoreFile, String keyStoreType, char[] privateKeyPassword, Class<? extends PrivateKey> expectedPrivateKeyClass) throws Exception {
        KeyStore ks = KeyStore.getInstance(keyStoreType, CryptoSupportProvider.getInstance());
        Assertions.assertNotNull(ks);
        
        ks.load(getResource(keyStoreFile), null);
        Assertions.assertEquals(1, ks.size());

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (!ks.isKeyEntry(alias)) {
                Assertions.fail();
            }
            Key k = ks.getKey(alias, privateKeyPassword);
            Assertions.assertNotNull(k);
            if (!expectedPrivateKeyClass.isAssignableFrom(k.getClass())) {
                Assertions.fail();
            }
        }
    }

    @Test
    public void testPlainPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048.pem", "PemKeyStore", null, RSAPrivateKey.class);
    }

    @Test
    public void testAes128EncryptedPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048-aes128.pem", "PemKeyStore", "password".toCharArray(), RSAPrivateKey.class);
    }

    @Test
    public void testAes256EncryptedPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048-aes256.pem", "PemKeyStore", "password".toCharArray(), RSAPrivateKey.class);
    }

    @Test
    public void testPlainPrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256.pem", "PemKeyStore", null, ECPrivateKey.class);
    }

    @Test
    public void testAes128PrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256-aes128.pem", "PemKeyStore", "password".toCharArray(), ECPrivateKey.class);
    }

    @Test
    public void testAes256PrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256-aes256.pem", "PemKeyStore", "password".toCharArray(), ECPrivateKey.class);
    }

    @Test
    public void testRsaKeystoreWithChain() throws Exception {
        String keyStoreFile = "rsa-keystore.pem";
        String keyStoreType = "PemKeyStore"; 
        char[] privateKeyPassword = "password".toCharArray();
        Class<? extends PrivateKey> expectedPrivateKeyClass = RSAPrivateKey.class;
        
        KeyStore ks = KeyStore.getInstance(keyStoreType, CryptoSupportProvider.getInstance());
        Assertions.assertNotNull(ks);
        
        ks.load(getResource(keyStoreFile), null);
        Assertions.assertEquals(1, ks.size());

        Enumeration<String> aliasEnum = ks.aliases();
        if (!aliasEnum.hasMoreElements()) {
            Assertions.fail();
        }
        String alias = aliasEnum.nextElement();
        if (!ks.isKeyEntry(alias)) {
            Assertions.fail();
        }
        Key k = ks.getKey(alias, privateKeyPassword);
        Assertions.assertNotNull(k);
        if (!expectedPrivateKeyClass.isAssignableFrom(k.getClass())) {
            Assertions.fail();
        }
        
        List<Certificate> certChain = Arrays.asList(ks.getCertificateChain(alias));
        List<Certificate> expectedCertChain = List.of(
            getRessourceCertificate("www.doesnotexist.org.crt"),
            getRessourceCertificate("Test-Intermediate-CA.crt"),
            getRessourceCertificate("Test-Root-CA.crt")
            );
        Assertions.assertEquals(expectedCertChain, certChain);
            
        Assertions.assertTrue(PemKeystore.matching(certChain.get(0).getPublicKey(), (PrivateKey) k));
    }

}