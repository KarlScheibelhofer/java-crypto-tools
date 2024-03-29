package dev.scheibelhofer.crypto.provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PemFileKeystoreTest {

    @Test
    public void testLoadPemTruststore() throws Exception {
        JctProvider prov = new JctProvider();

        KeyStore ks = KeyStore.getInstance("pem", prov);
        Assertions.assertNotNull(ks);

        ks.load(PemKeystoreTest.getResource("truststore.pem"), null);
        Assertions.assertEquals(4, ks.size());

        Set<Certificate> certSet = new HashSet<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        certSet.add(cf.generateCertificate(PemKeystoreTest.getResource("github.com.crt")));
        certSet.add(cf.generateCertificate(PemKeystoreTest.getResource("google.com.crt")));
        certSet.add(cf.generateCertificate(PemKeystoreTest.getResource("microsoft.com.crt")));
        certSet.add(cf.generateCertificate(PemKeystoreTest.getResource("orf.at.crt")));

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
                    Assertions.fail("invalid cert type");
                }
            } else {
                Assertions.fail("found unexpected non-certificate entry with alias: " + alias);
            }
        }
    }

    public void checkPrivateKey(String keyStoreFile, String keyStoreType, char[] privateKeyPassword,
            Class<? extends PrivateKey> expectedPrivateKeyClass) throws Exception {
        KeyStore ks = KeyStore.getInstance(keyStoreType, JctProvider.getInstance());
        Assertions.assertNotNull(ks);

        ks.load(PemKeystoreTest.getResource(keyStoreFile), null);
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
    public void testLoadPlainPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048.pem", "pem", null, RSAPrivateKey.class);
    }

    @Test
    public void testLoadAes128EncryptedPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048-aes128.pem", "pem", "password".toCharArray(), RSAPrivateKey.class);
    }

    @Test
    public void testLoadAes256EncryptedPrivateKeyRSA() throws Exception {
        checkPrivateKey("rsa-2048-aes256.pem", "pem", "password".toCharArray(), RSAPrivateKey.class);
    }

    @Test
    public void testLoadPlainPrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256.pem", "pem", null, ECPrivateKey.class);
    }

    @Test
    public void testLoadAes128PrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256-aes128.pem", "pem", "password".toCharArray(), ECPrivateKey.class);
    }

    @Test
    public void testLoadAes256PrivateKeyEC() throws Exception {
        checkPrivateKey("ec-p256-aes256.pem", "pem", "password".toCharArray(), ECPrivateKey.class);
    }

    @Test
    public void testLoadRsaKeystoreWithChain() throws Exception {
        checkKeystoreWithChain("RSA");
    }

    @Test
    public void testLoadEcKeystoreWithChain() throws Exception {
        checkKeystoreWithChain("EC");
    }

    public void checkKeystoreWithChain(String algorithm) throws Exception {
        String keyStoreFile = "www.doesnotexist.org-" + algorithm + "-keystore.pem";
        String keyStoreType = "pem";
        char[] privateKeyPassword = "password".toCharArray();

        KeyStore ks = KeyStore.getInstance(keyStoreType, JctProvider.getInstance());
        Assertions.assertNotNull(ks);

        ks.load(PemKeystoreTest.getResource(keyStoreFile), null);
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
        if (!(k instanceof PrivateKey)) {
            Assertions.fail();
        }

        List<Certificate> certChain = Arrays.asList(ks.getCertificateChain(alias));
        List<Certificate> expectedCertChain = List.of(
            PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-" + algorithm + ".crt"),
            PemKeystoreTest.getResourceCertificate("Test-Intermediate-CA-" + algorithm + ".crt"),
            PemKeystoreTest.getResourceCertificate("Test-Root-CA-" + algorithm + ".crt"));
        Assertions.assertEquals(expectedCertChain, certChain);

        Assertions.assertTrue(PemKeystore.matching(certChain.get(0).getPublicKey(), (PrivateKey) k));
    }

    @Test
    public void testLoadRsaKeystoreChainAlias() throws Exception {
        File originalKeystore = new File("src/test/resources", "www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String expectedAlias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        PrivateKey privateKey = (PrivateKey) ks.getKey(expectedAlias, null);
        Assertions.assertNotNull(privateKey);

        Certificate[] certChain = ks.getCertificateChain(expectedAlias);
        Assertions.assertNotNull(certChain);
    }

    @Test
    public void testStoreRsaKeystoreWithChain() throws Exception {
        File originalKeystore = new File("src/test/resources", "www.doesnotexist.org-RSA-keystore.pem");
        File savedKeystore = new File("src/test/resources/out/", originalKeystore.getName());
        char[] password = "password".toCharArray();

        KeyStore ks = loadKeyStore(originalKeystore, password);

        savedKeystore.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(savedKeystore)) {
            ks.store(fos, password);
        }

        PemKeystoreTest.assertFilesEqual(originalKeystore, savedKeystore);
    }

    private KeyStore loadKeyStore(File keyStoreFile, char[] password) throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(new FileInputStream(keyStoreFile), password);
        return ks;
    }

    @Test
    public void testLoadDes3PrivateKey() throws Exception {
        // generated with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
        // -out private-key-des3.pem -pass pass:password -des3
        File originalKeystore = new File("src/test/resources", "private-key-des3.pem");
        char[] password = "password".toCharArray();

        try {
            loadKeyStore(originalKeystore, password);
            Assertions.fail();
        } catch (IOException e) {
            // that is expected du to unsupported Des3 encrypted private keys
        }

        // converted with: openssl pkey -in private-key-des3.pem -passin pass:password
        // -out private-key-aes128.pem -passout pass:password -aes128

        File aesEncryptedKeystore = new File("src/test/resources", "private-key-aes128.pem");
        loadKeyStore(aesEncryptedKeystore, password);
    }

    @Test
    public void testCreateRsaKeystoreWithChain() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(null, null);

        File certFile = new File("src/test/resources", "www.doesnotexist.org-RSA.crt");
        File caCertFile = new File("src/test/resources", "Test-Intermediate-CA-RSA.crt");
        File rootCertFile = new File("src/test/resources", "Test-Root-CA-RSA.crt");
        File keyFile = new File("src/test/resources", "www.doesnotexist.org-RSA.pem");
        String password = "password";
        String alias = "www.doesnotexist.org-RSA";

        PrivateKey privateKey = PemKeystoreTest.readPrivateKey(keyFile, "RSA", password);
        X509Certificate certificate = PemKeystoreTest.readCertificate(certFile);
        X509Certificate caCertificate = PemKeystoreTest.readCertificate(caCertFile);
        X509Certificate rootCertificate = PemKeystoreTest.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };
        ks.setKeyEntry(alias, privateKey, null, certChain);

        File keystoreFile = new File("src/test/resources/out/", "www.doesnotexist.org-RSA-keystore-created.pem");
        keystoreFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        File expectedKeystore = new File("src/test/resources", "www.doesnotexist.org-RSA-keystore-alias.pem");
        PemKeystoreTest.assertFilesEqual(expectedKeystore, keystoreFile);
    }

    @Test
    public void testCreateRsaKeystoreWithChainAndPW() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(null, null);

        File certFile = new File("src/test/resources", "www.doesnotexist.org-RSA.crt");
        File caCertFile = new File("src/test/resources", "Test-Intermediate-CA-RSA.crt");
        File rootCertFile = new File("src/test/resources", "Test-Root-CA-RSA.crt");
        File keyFile = new File("src/test/resources", "www.doesnotexist.org-RSA.pem");
        String password = "password";
        String alias = "www.doesnotexist.org-RSA";

        PrivateKey privateKey = PemKeystoreTest.readPrivateKey(keyFile, "RSA", password);
        X509Certificate certificate = PemKeystoreTest.readCertificate(certFile);
        X509Certificate caCertificate = PemKeystoreTest.readCertificate(caCertFile);
        X509Certificate rootCertificate = PemKeystoreTest.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };
        ks.setKeyEntry(alias, privateKey, password.toCharArray(), certChain);

        File keystoreFile = new File("src/test/resources/out/", "www.doesnotexist.org-RSA-keystore-created2.pem");
        keystoreFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        assertEquals(1, ks.size());
        
        KeyStore ksReloaded = KeyStore.getInstance("pem", JctProvider.getInstance());
        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
            ksReloaded.load(fis, password.toCharArray());
        }
        assertEquals(1, ksReloaded.size());
        assertTrue(ksReloaded.containsAlias(alias));
        assertTrue(ksReloaded.isKeyEntry(alias));

        assertEquals(privateKey, ksReloaded.getKey(alias, password.toCharArray()));
        assertArrayEquals(certChain, ksReloaded.getCertificateChain(alias));
    }

    @Test
    public void testCreateTrustKeystore() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(null, null);

        List<File> caFileList = Arrays.asList(
                new File("src/test/resources", "lets-encrypt-ca-R3.crt"),
                new File("src/test/resources", "lets-encrypt-root-ISRG-Root-X1.crt"),
                new File("src/test/resources", "Test-Intermediate-CA-RSA.crt"),
                new File("src/test/resources", "Test-Root-CA-RSA.crt"));

        for (File certFile : caFileList) {
            X509Certificate certificate = PemKeystoreTest.readCertificate(certFile);
            String alias = certFile.getName().replaceFirst("[.][^.]+$", "");
            ks.setCertificateEntry(alias, certificate);
        }

        File keystoreFile = new File("src/test/resources/out/", "ca-truststore-created.pem");
        keystoreFile.getParentFile().mkdirs();
        String password = "password";
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        File expectedKeystore = new File("src/test/resources", "ca-truststore.pem");
        PemKeystoreTest.assertFilesEqual(expectedKeystore, keystoreFile);
    }

    @Test
    public void testDeleteKeyAndChain() throws Exception {
        File originalKeystore = new File("src/test/resources", "www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String alias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        ks.deleteEntry(alias);

        assertFalse(ks.containsAlias(alias));
    }

    @Test
    public void testCreationDate() throws Exception {
        File originalKeystore = new File("src/test/resources", "www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String alias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        Date creationDate = ks.getCreationDate(alias);

        assertNotNull(creationDate);
    }

    @Test
    public void testGetCertificateAlias() throws Exception {
        File originalKeystore = new File("src/test/resources", "truststore.pem");
        char[] password = "password".toCharArray();

        KeyStore ks = loadKeyStore(originalKeystore, password);

        boolean checked = false;
        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String expectedAlias = aliasEnum.nextElement();
            if (ks.isCertificateEntry(expectedAlias)) {
                Certificate c = ks.getCertificate(expectedAlias);
                String a = ks.getCertificateAlias(c);
                assertEquals(expectedAlias, a);
                // to ensure this loop checked at least one entry
                checked = true;
            }
        }
        assertTrue(checked);

        assertNull(ks.getCertificateAlias(null));
    }

    @Test
    public void testGetCertificateChainAlias() throws Exception {
        File originalKeystore = new File("src/test/resources", "www.doesnotexist.org-RSA-keystore.pem");
        char[] password = "password".toCharArray();
        String alias = "CN=www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(originalKeystore, password);

        X509Certificate eeCert = PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-RSA.crt");
        String eeCertAlias = ks.getCertificateAlias(eeCert);

        assertEquals(alias, eeCertAlias);
    }

    @Test
    public void testGetCertificateAliasEmptyChain() throws Exception {

        checkPrivateKey("rsa-2048.pem", "pem", null, RSAPrivateKey.class);
    }    

    @Test
    public void testReadAlias() throws Exception {
        File keystore = new File("src/test/resources", "www.doesnotexist.org-RSA-keystore-alias.pem");
        char[] password = "password".toCharArray();
        String alias = "www.doesnotexist.org-RSA";

        KeyStore ks = loadKeyStore(keystore, password);

        assertTrue(ks.isKeyEntry(alias));
        Key pk = ks.getKey(alias, password);
        assertNotNull(pk);

        Certificate[] cc = ks.getCertificateChain(alias);
        assertNotNull(cc);
        assertEquals(3, cc.length);
    }

    @Test
    public void testStorePemTruststore() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(null, null);

        ks.setCertificateEntry("github.com", PemKeystoreTest.getResourceCertificate("github.com.crt"));
        ks.setCertificateEntry("google.com", PemKeystoreTest.getResourceCertificate("google.com.crt"));
        ks.setCertificateEntry("microsoft.com", PemKeystoreTest.getResourceCertificate("microsoft.com.crt"));
        ks.setCertificateEntry("orf.at", PemKeystoreTest.getResourceCertificate("orf.at.crt"));

        File truststoreFile = new File("src/test/resources/out/", "truststore-alias-created.pem");
        truststoreFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(truststoreFile)) {
            ks.store(fos, null);
        }

        File expectedTruststoreFile = new File("src/test/resources/", "truststore-alias.pem");
        PemKeystoreTest.assertFilesEqual(expectedTruststoreFile, truststoreFile);
    }

    private static byte[] readPemData(File pemFile) throws Exception {
        String pemKey = Files.readAllLines(pemFile.toPath()).stream().filter(s -> !s.startsWith("-----"))
                .collect(Collectors.joining(""));
        return Base64.getDecoder().decode(pemKey);
    }

    @Test
    public void testStoreEncryptedRSAKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(null, null);

        File certFile = new File("src/test/resources", "www.doesnotexist.org-RSA.crt");
        File caCertFile = new File("src/test/resources", "Test-Intermediate-CA-RSA.crt");
        File rootCertFile = new File("src/test/resources", "Test-Root-CA-RSA.crt");
        File keyFile = new File("src/test/resources", "www.doesnotexist.org-RSA-enc.pem");
        String password = "password";
        String alias = "www.doesnotexist.org-RSA";

        byte[] encryptedPrivateKey = readPemData(keyFile);
        X509Certificate certificate = PemKeystoreTest.readCertificate(certFile);
        X509Certificate caCertificate = PemKeystoreTest.readCertificate(caCertFile);
        X509Certificate rootCertificate = PemKeystoreTest.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };

        ks.setKeyEntry(alias, encryptedPrivateKey, certChain);

        File keystoreFile = new File("src/test/resources/out/", "www.doesnotexist.org-RSA-enc-keystore-created.pem");
        keystoreFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password.toCharArray());
        }

        File expectedKeystore = new File("src/test/resources", "www.doesnotexist.org-RSA-enc-keystore.pem");
        PemKeystoreTest.assertFilesEqual(expectedKeystore, keystoreFile);
    }

    @Test
    public void loadMozillaRootStore4TLS() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());

        // file from
        // "https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"
        File mozillaTruststoreFile = new File("src/test/resources/", "IncludedRootsPEM.txt");
        try (FileInputStream is = new FileInputStream(mozillaTruststoreFile)) {
            ks.load(is, null);
        }
        Assertions.assertTrue(ks.size() > 0);

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (ks.isCertificateEntry(alias)) {
                Certificate c = ks.getCertificate(alias);
                Assertions.assertNotNull(c);
                if (c instanceof X509Certificate) {
                    X509Certificate xc = (X509Certificate) c;
                    String subjectDN = xc.getSubjectX500Principal().getName();
                    Assertions.assertTrue(alias.startsWith(subjectDN));
                } else {
                    Assertions.fail("invalid certificate entry not of type X509Certificate, alias: " + alias);
                }
            } else {
                Assertions.fail("invalid keystore entry not of type trusted certificate, alias: " + alias);
            }
        }
    }

    @Test
    public void testLoadPemTruststoreAliasExplanatory() throws Exception {
        JctProvider prov = new JctProvider();

        KeyStore ks = KeyStore.getInstance("pem", prov);
        Assertions.assertNotNull(ks);

        ks.load(PemKeystoreTest.getResource("truststore-alias-explanatory.pem"), null);
        Assertions.assertEquals(4, ks.size());

        Assertions.assertEquals(PemKeystoreTest.getResourceCertificate("github.com.crt"), ks.getCertificate("github.com"));
        Assertions.assertEquals(PemKeystoreTest.getResourceCertificate("google.com.crt"), ks.getCertificate("google.com"));
        Assertions.assertEquals(PemKeystoreTest.getResourceCertificate("microsoft.com.crt"), ks.getCertificate("microsoft.com"));
        Assertions.assertEquals(PemKeystoreTest.getResourceCertificate("orf.at.crt"), ks.getCertificate("orf.at"));
    }

    @Test
    public void testGetViaAlias() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());        
        File keystoreFile = new File("src/test/resources/", "www.doesnotexist.org-EC-keystore-alias.pem");
        ks.load(new FileInputStream(keystoreFile), null);

        assertNull(ks.getKey("unknown-alias", null));
        assertNull(ks.getCertificate("unknown-alias"));
        assertNull(ks.getCertificateChain("unknown-alias"));

        assertNotNull(ks.getKey("www.doesnotexist.org-EC", null));
        assertNotNull(ks.getCertificateChain("www.doesnotexist.org-EC"));
        assertNotNull(ks.getCertificate("www.doesnotexist.org-EC"));
        Assertions.assertEquals(PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-EC.crt"), ks.getCertificate("www.doesnotexist.org-EC"));
    }

    @Test
    public void testLoadEnc() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());        
        File keystoreFile = new File("src/test/resources/", "www.doesnotexist.org-EC-enc.pem");
        ks.load(new FileInputStream(keystoreFile), null);

        assertNull(ks.getKey("unknown-alias", null));
        assertNull(ks.getCertificate("unknown-alias"));
        assertNull(ks.getCertificateChain("unknown-alias"));

        assertThrowsExactly(NoSuchAlgorithmException.class, () -> ks.getKey("private-key", null));
    }

    @Test
    public void testUnsupportedKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(null, null);

        assertThrowsExactly(KeyStoreException.class, () ->  ks.setKeyEntry("alias", null, null, null));
        
        PublicKey publicKey1a = PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-RSA.crt").getPublicKey();
        assertThrowsExactly(KeyStoreException.class, () ->  ks.setKeyEntry("alias", publicKey1a, null, null));
    }

    @Test
    public void testUnsupportedCertificate() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        ks.load(null, null);

        assertThrowsExactly(KeyStoreException.class, () ->  ks.setCertificateEntry("alias", null));
    }
}