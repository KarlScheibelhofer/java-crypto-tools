package dev.scheibelhofer.crypto.provider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import dev.scheibelhofer.crypto.provider.Pem.PrivateKeyEntry;

public class PemKeystoreTest {

    static InputStream getResource(String name) {
        return PemKeystoreTest.class.getClassLoader().getResourceAsStream(name);
    }

    static X509Certificate getResourceCertificate(String name) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(getResource(name));
    }

    static PrivateKey readPrivateKey(File keyFile, String algorithm, String password) throws Exception {
        String pemKey = Files.readAllLines(keyFile.toPath()).stream().filter(s -> !s.startsWith("-----"))
                .collect(Collectors.joining(""));
        byte[] encoding = Base64.getDecoder().decode(pemKey);
    
        AlgorithmParameters nullAlgorithmParam = AlgorithmParameters.getInstance("0.1", JctProvider.getInstance());
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(nullAlgorithmParam, encoding);
        Cipher nullCipher = Cipher.getInstance("null", JctProvider.getInstance());
        nullCipher.init(Cipher.DECRYPT_MODE, new NullPrivateKey());
        PKCS8EncodedKeySpec spec = epki.getKeySpec(nullCipher);
    
        KeyFactory kf = KeyFactory.getInstance(spec.getAlgorithm());
    
        return kf.generatePrivate(spec);
    }

    static X509Certificate readCertificate(File certFile) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certFile)) {
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }

    static void assertFilesEqual(File expectedFile, File realFile) throws Exception {
        assertFilesEqual(expectedFile.toPath(), realFile.toPath());
    }

    static void assertFilesEqual(Path expectedPath, Path realPath) throws Exception {
        Assertions.assertArrayEquals(Files.readAllBytes(expectedPath), Files.readAllBytes(realPath));
    }

    @Test
    public void testInstance() throws Exception {
        assertNotNull(KeyStore.getInstance("pem", JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("PEM", JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("Pem", JctProvider.getInstance()));
        
        assertNotNull(KeyStore.getInstance("pem-directory", JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("PEM-DIRECTORY", JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("Pem-Directory", JctProvider.getInstance()));
    }

    @Test
    public void testInstallProvider() throws Exception {
        assertThat(Security.addProvider(JctProvider.getInstance()), is(greaterThanOrEqualTo(0)));

        assertNotNull(KeyStore.getInstance("pem").getProvider().equals(JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("PEM").getProvider().equals(JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("Pem").getProvider().equals(JctProvider.getInstance()));
        
        assertNotNull(KeyStore.getInstance("pem-directory").getProvider().equals(JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("PEM-DIRECTORY").getProvider().equals(JctProvider.getInstance()));
        assertNotNull(KeyStore.getInstance("Pem-Directory").getProvider().equals(JctProvider.getInstance()));        

        Security.removeProvider(JctProvider.getInstance().getName());
    }

    @Test
    public void testNullPrivateKey() throws Exception {
        PrivateKey k = new NullPrivateKey();
        assertEquals("null", k.getAlgorithm());
        assertEquals("null", k.getFormat());
        assertNull(k.getEncoded());
    }

    @Test
    public void testNullAlgorithmParameters() throws Exception {
        AlgorithmParameters.getInstance("null", JctProvider.getInstance()).init(null, null);
        AlgorithmParameters.getInstance("null", JctProvider.getInstance()).init((byte[]) null);
        AlgorithmParameters.getInstance("null", JctProvider.getInstance()).init((AlgorithmParameterSpec) null);
        AlgorithmParameters ap = AlgorithmParameters.getInstance("null", JctProvider.getInstance());
        ap.init((byte[]) null);
        assertThrows(UnsupportedOperationException.class,() -> ap.getParameterSpec(null));
        assertThrows(UnsupportedOperationException.class,() -> ap.getEncoded());
        assertThrows(UnsupportedOperationException.class,() -> ap.getEncoded(null));
        assertEquals("null", ap.toString());
    }

    @Test
    public void testPBES2AlgorithmParameters() throws Exception {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(new byte[8], 2048, new IvParameterSpec(new byte[16]));
        AlgorithmParameters pbeAlgParams = AlgorithmParameters.getInstance("PBES2", JctProvider.getInstance());
        pbeAlgParams.init(pbeParamSpec);

        AlgorithmParameters.getInstance("PBES2", JctProvider.getInstance()).init(pbeAlgParams.getEncoded(), "any");
        AlgorithmParameters.getInstance("PBES2", JctProvider.getInstance()).init(pbeAlgParams.getEncoded());
        AlgorithmParameters.getInstance("PBES2", JctProvider.getInstance()).init(pbeParamSpec);
        AlgorithmParameters ap = AlgorithmParameters.getInstance("PBES2", JctProvider.getInstance());
        ap.init(pbeAlgParams.getEncoded());
        assertNotNull(ap.getParameterSpec(PBEParameterSpec.class));
        assertNotNull(ap.getEncoded());
        assertNotNull(ap.getEncoded("any"));
        assertEquals("PBEWithHmacSHA256AndAES_256", ap.toString());
    }

    @Test
    public void testNullCipher() throws Exception {
        Cipher c = Cipher.getInstance("null/mode/padding", JctProvider.getInstance());
        assertEquals(16, c.getBlockSize());
        assertNull(c.getIV());
        assertThrows(UnsupportedOperationException.class,() -> c.getParameters());
        c.init(Cipher.ENCRYPT_MODE, new NullPrivateKey(), SecureRandom.getInstance("NativePRNGNonBlocking"));
        c.init(Cipher.ENCRYPT_MODE, new NullPrivateKey(), new IvParameterSpec(new byte[16]), SecureRandom.getInstance("NativePRNGNonBlocking"));
        c.init(Cipher.ENCRYPT_MODE, new NullPrivateKey(), AlgorithmParameters.getInstance("null", JctProvider.getInstance()), SecureRandom.getInstance("NativePRNGNonBlocking"));

        byte[] series = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        assertArrayEquals(series, c.update(series));

        assertArrayEquals(series, c.update(series, 0, 16));

        byte[] out = new byte[series.length];
        c.update(series, 0, 16, out);
        assertArrayEquals(series, out);
        
        assertArrayEquals(series, c.doFinal(series));
        assertEquals(16, c.doFinal(series, 0, 16, out, 0));
        assertArrayEquals(series, out);

        assertEquals(16, c.getOutputSize(16));
    }

     @Test
    public void testMatching() throws Exception {
       assertFalse(PemKeystore.matching((ECPublicKey) null, (ECPrivateKey) null));

       PublicKey publicKey1a = PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-RSA.crt").getPublicKey();
       PrivateKey privateKey1a = PemKeystoreTest.readPrivateKey(new File("src/test/resources", "www.doesnotexist.org-RSA.pem"), "RSA", null);
       
       PublicKey publicKey1b = PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-RSA.crt").getPublicKey();
       
       PrivateKey privateKeyRSA = PemKeystoreTest.readPrivateKey(new File("src/test/resources", "rsa-2048.pem"), "RSA", null);
       PrivateKey privateKeyEC = PemKeystoreTest.readPrivateKey(new File("src/test/resources", "ec-p256.pem"), "EC", null);
       PublicKey publicKeyEC = PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-EC.crt").getPublicKey();
       
       assertTrue(PemKeystore.matching(publicKey1a, privateKey1a));
       assertTrue(PemKeystore.matching(publicKey1b, privateKey1a));
       assertFalse(PemKeystore.matching(publicKey1a, privateKeyRSA));
       assertFalse(PemKeystore.matching(publicKey1a, privateKeyEC));
       assertFalse(PemKeystore.matching(publicKeyEC, privateKeyRSA));
    }

    @Test
    public void testMatchingIDs() throws Exception {
       assertTrue(PemKeystore.matchingKeyIDs(null, null));
       
       X509Certificate cert = PemKeystoreTest.getResourceCertificate("www.doesnotexist.org-RSA.crt");
       assertTrue(PemKeystore.matchingKeyIDs(null, cert));
       
       X509Certificate mockCert = mock(X509Certificate.class, CALLS_REAL_METHODS);
       String SUBJECT_KEY_ID = "2.5.29.14";
       when(mockCert.getExtensionValue(SUBJECT_KEY_ID)).thenReturn(null);
       assertTrue(PemKeystore.matchingKeyIDs(new byte[] {1, 2, 3}, mockCert));
    }

    @Test
    public void testMakeUniqueAlias() throws Exception {
       String alias = PemKeystore.makeUniqueAlias(Collections.emptySet(), new Pem.UnknownEntry(null, "-----BEGIN UNKNOWN-----"));
       assertNotNull(alias);
       assertThat(alias, startsWith("entry"));
    }

    @Test
    public void testGetCertificateAliasUnknown() throws Exception {
        // cannot touch all code branches via regular KeyStore API
        
        PemFileKeystore pemFileKeystoreEngine = new PemFileKeystore();

        PrivateKey privateKey = PemKeystoreTest.readPrivateKey(new File("src/test/resources", "rsa-2048.pem"), "RSA", null);

        Certificate[] chain0 = new Certificate[0];
        pemFileKeystoreEngine.engineSetKeyEntry("alias", privateKey, null, chain0);

        X509Certificate mockCert = mock(X509Certificate.class);
        assertNull(pemFileKeystoreEngine.engineGetCertificateAlias(mockCert));
        
        Certificate[] chain1 = new Certificate[] { mockCert };
        pemFileKeystoreEngine.engineSetKeyEntry("alias", privateKey, null, chain1);
        X509Certificate mockCert2 = mock(X509Certificate.class);
        assertNull(pemFileKeystoreEngine.engineGetCertificateAlias(mockCert2));
    }

    @Test
    public void testContainsAliasKS() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());        
        File keystoreFile = new File("src/test/resources/", "rsa-2048.pem");
        ks.load(new FileInputStream(keystoreFile), null);

        assertTrue(ks.containsAlias("private-key"));
        assertFalse(ks.containsAlias("unknown-key"));
    }
        
    @Test
    public void testContainsAliasTS() throws Exception {
        KeyStore ts = KeyStore.getInstance("pem", JctProvider.getInstance());        
        File truststoreFile = new File("src/test/resources/", "truststore.pem");
        ts.load(new FileInputStream(truststoreFile), null);

        assertTrue(ts.containsAlias("CN=github.com,O=GitHub\\, Inc.,L=San Francisco,ST=California,C=US"));
        assertFalse(ts.containsAlias("unknown-certificate"));
    }

    @Test
    public void testPrivateKeyNullBranch() throws Exception {
        // cannot touch all code branches via regular KeyStore API
        
        PemFileKeystore pemFileKeystoreEngine = new PemFileKeystore();

        PrivateKey privateKey = PemKeystoreTest.readPrivateKey(new File("src/test/resources", "rsa-2048.pem"), "RSA", null);
        String alias = "alias";

        Certificate[] chain0 = new Certificate[0];
        pemFileKeystoreEngine.engineSetKeyEntry(alias, privateKey, null, chain0);

        PrivateKeyEntry privateKeyEntry = pemFileKeystoreEngine.privateKeys.get(alias);
        privateKeyEntry.privateKey = null;

        assertNull(pemFileKeystoreEngine.engineGetKey(alias, null));
    }
        
}