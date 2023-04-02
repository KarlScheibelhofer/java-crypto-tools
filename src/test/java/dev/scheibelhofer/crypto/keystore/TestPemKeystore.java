package dev.scheibelhofer.crypto.keystore;

import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import dev.scheibelhofer.crypto.provider.CryptoSupportProvider;

public class TestPemKeystore {

    InputStream getResource(String name) {
        return getClass().getClassLoader().getResourceAsStream(name);
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

    @Test
    public void testPrivateKey() throws Exception {
        CryptoSupportProvider prov = new CryptoSupportProvider();

        KeyStore ks = KeyStore.getInstance("PemKeyStore", prov);
        Assertions.assertNotNull(ks);
        
        ks.load(getResource("rsa-2048.pem"), null);
        Assertions.assertEquals(1, ks.size());

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (ks.isKeyEntry(alias)) {
                Key k = ks.getKey(alias, null);
                Assertions.assertNotNull(k);
                if (k instanceof RSAPrivateCrtKey) {
                    RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) k;
                    Assertions.assertNotNull(rsaKey);
                } else {
                    Assertions.fail();
                }
            } else {
                Assertions.fail();
            }
        }

    }
}