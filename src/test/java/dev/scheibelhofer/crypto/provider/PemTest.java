package dev.scheibelhofer.crypto.provider;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

import dev.scheibelhofer.crypto.provider.Pem.CertificateEntry;

public class PemTest {

    @Test
    public void testPemInvalidCertificate() throws Exception {
        X509Certificate mockedCert = mock(X509Certificate.class, CALLS_REAL_METHODS);
        doThrow(new CertificateEncodingException("intentionally for testing")).when(mockedCert).getEncoded();
       
        assertThrowsExactly(PemKeystoreException.class, () -> new Pem.CertificateEntry("alias", mockedCert));
        
        assertThrowsExactly(PemKeystoreException.class, () -> new Pem.CertificateEntry("alias").initFromEncoding(new byte[] { 1, 2, 3, 4}));
    }

    @Test
    public void testPemInvalidPrivateKey() throws Exception {
        assertThrowsExactly(PemKeystoreException.class, () -> new Pem.PrivateKeyEntry("alias").initFromEncoding(new byte[] { 1, 2, 3, 4}));
    }

    @Test
    public void testCertificateEntry() throws Exception {
        X509Certificate cert1a = TestPemKeystore.getResourceCertificate("www.doesnotexist.org-RSA.crt");
        X509Certificate cert1b = TestPemKeystore.getResourceCertificate("www.doesnotexist.org-RSA.crt");
        // X509Certificate cert2 = TestPemKeystore.getResourceCertificate("www.doesnotexist.org-EC.crt");

        CertificateEntry ce0a = new Pem.CertificateEntry("alias");
        CertificateEntry ce0b = new Pem.CertificateEntry("alias");
        CertificateEntry ce1a = new Pem.CertificateEntry("alias", cert1a);
        CertificateEntry ce1b = new Pem.CertificateEntry("alias", cert1b);
        // CertificateEntry ce2 = new Pem.CertificateEntry("alias", cert2);

        assertFalse(ce1a.equals(null));
        assertFalse(ce1a.equals(""));
        assertFalse(ce0a.equals(ce1a));
        assertTrue(ce0a.equals(ce0b));
        assertTrue(ce1a.equals(ce1b));

        ce0a.hashCode();
    }

    @Test
    public void testPrivateKeyEncryptionException() throws Exception {
        PrivateKey mockedKey = mock(PrivateKey.class, CALLS_REAL_METHODS);
        when(mockedKey.getAlgorithm()).thenReturn("invalid-algorithm-name");

        char[] password = null;
        assertThrowsExactly(PemKeystoreException.class, () -> new Pem.EncryptedPrivateKeyEntry("alias", mockedKey, password));
    }
}
