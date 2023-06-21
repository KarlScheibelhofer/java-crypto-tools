package dev.scheibelhofer.crypto.provider;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import java.security.cert.X509Certificate;

import java.security.cert.CertificateEncodingException;

import org.junit.jupiter.api.Test;

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
    
}
