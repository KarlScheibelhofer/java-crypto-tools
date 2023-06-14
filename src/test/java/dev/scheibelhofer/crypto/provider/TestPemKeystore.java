package dev.scheibelhofer.crypto.provider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.IvParameterSpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TestPemKeystore {

    static InputStream getResource(String name) {
        return TestPemKeystore.class.getClassLoader().getResourceAsStream(name);
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
}