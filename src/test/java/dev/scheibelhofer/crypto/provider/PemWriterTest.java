package dev.scheibelhofer.crypto.provider;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.Test;

import dev.scheibelhofer.crypto.provider.Pem.UnknownEntry;

public class PemWriterTest {

    static class ExOutputStream extends OutputStream {

            @Override
            public void write(int b) throws IOException {
                throw new IOException("Unimplemented method 'write(int)'");
            }
            
        };

    @Test
    public void testClose() throws Exception {
        OutputStream mockedOS = mock(OutputStream.class);
        
        PemWriter pw = new PemWriter(mockedOS, false);
        pw.close();
        
        verify(mockedOS).close();
    }
    
    @Test
    public void testFlush() throws Exception {
        OutputStream mockedOS = mock(OutputStream.class);
        
        PemWriter pw = new PemWriter(mockedOS, false);
        pw.flush();
        
        verify(mockedOS).flush();
        
        pw.close();
    }
    
    @Test
    public void testWriteEntryEx() throws Exception {
        OutputStream exceptionOS = new ExOutputStream();

        PemWriter pw = new PemWriter(exceptionOS, false);
        X509Certificate cert = PemKeystoreTest.getResourceCertificate("github.com.crt");
        assertThrowsExactly(PemKeystoreException.class, () -> pw.writeEntry(new Pem.CertificateEntry("github.com", cert)));

        pw.close();
    }

    @Test
    public void testWriteToPath() throws Exception {
        File f = new File("src/test/resources/read-only");
        f.createNewFile();
        f.setReadOnly();
        final X509Certificate cert = PemKeystoreTest.getResourceCertificate("github.com.crt");
        assertThrowsExactly(PemKeystoreException.class, () -> PemWriter.write(f.toPath(), new Pem.CertificateEntry("github.com", cert)));
        f.delete();
    }

    @Test
    public void testWriteListToPath() throws Exception {
        File f = new File("src/test/resources/read-only");
        f.createNewFile();
        f.setReadOnly();
        final X509Certificate cert = PemKeystoreTest.getResourceCertificate("github.com.crt");
        assertThrowsExactly(PemKeystoreException.class, () -> PemWriter.write(f.toPath(), List.of(new Pem.CertificateEntry("github.com", cert))));
        f.delete();
    }

    @Test
    public void testWriteUnknownEntry() throws Exception {
        OutputStream mockedOS = mock(OutputStream.class);
        
        PemWriter pw = new PemWriter(mockedOS, false);
        UnknownEntry e = new Pem.UnknownEntry("null", "-----BEGIN UNKNOWN-----");
        e.encoding = new byte[] { 1,2,3 };
        pw.writeEntry(e);
        
        pw.close();
    }

    @Test
    public void testWriteNullEntry() throws Exception {
        OutputStream mockedOS = mock(OutputStream.class);
        
        PemWriter pw = new PemWriter(mockedOS, false);
        Pem.Entry e = null;
        assertThrowsExactly(NullPointerException.class, () -> pw.writeEntry(e));
        
        pw.close();
    }

    @Test
    public void testWriteNullTypeEntry() throws Exception {
        OutputStream mockedOS = mock(OutputStream.class);
        
        PemWriter pw = new PemWriter(mockedOS, false);
        Pem.Entry e = new Pem.UnknownEntry("null", "-----BEGIN UNKNOWN-----");;
        e.type = null;
        assertThrowsExactly(NullPointerException.class, () -> pw.writeEntry(e));
        
        pw.close();
    }

}
