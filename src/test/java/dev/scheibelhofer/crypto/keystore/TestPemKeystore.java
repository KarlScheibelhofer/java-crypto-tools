package dev.scheibelhofer.crypto.keystore;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
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

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String a = aliases.nextElement();
            if (ks.isCertificateEntry(a)) {
                Certificate c = ks.getCertificate(a);
                Assertions.assertNotNull(c);
                Assertions.assertTrue(certSet.contains(c));
            } else {
                Assertions.fail();
            }
        }
    }
}