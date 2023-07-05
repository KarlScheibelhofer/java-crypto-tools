package dev.scheibelhofer.crypto.provider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class TestPemDirectoryKeystore {

    @Test
    public void loadTruststoreDirectory() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        String caCertsDirPath = Paths.get("src/test/resources/ca-certificates").toFile().getAbsolutePath();
        Path pemKeystoreDirFile = Paths.get("src/test/resources/out", "ca-certificates.pem-folder");
        pemKeystoreDirFile.getParent().toFile().mkdirs();
        Files.writeString(pemKeystoreDirFile, caCertsDirPath, StandardCharsets.UTF_8);

        try (FileInputStream is = new FileInputStream(pemKeystoreDirFile.toFile())) {
            ks.load(is, null);
        }
        Assertions.assertEquals(3, ks.size());
    }

    @Test
    public void loadTruststoreDirectoryShort() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        try (InputStream is = new ByteArrayInputStream(
                "src/test/resources/ca-certificates".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        Assertions.assertEquals(3, ks.size());
    }

    @Test
    public void storeTruststoreDirectory() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());
        ks.load(null, null);

        Path caCertsDirPath = Paths.get("src/test/resources/out/truststore-dir");
        deleteDirectory(caCertsDirPath);

        Path pemKeystoreDirFile = Paths.get("src/test/resources/out/truststore.pem-directory");
        pemKeystoreDirFile.getParent().toFile().mkdirs();
        Files.writeString(pemKeystoreDirFile, caCertsDirPath.toFile().getAbsolutePath(), StandardCharsets.UTF_8);

        try (FileInputStream is = new FileInputStream(pemKeystoreDirFile.toFile())) {
            ks.load(is, null);
        }

        ks.setCertificateEntry("test-root-ca-rsa", TestPemKeystore.getResourceCertificate("Test-Root-CA-RSA.crt"));
        ks.setCertificateEntry("test-intermediate-ca-rsa",
                TestPemKeystore.getResourceCertificate("Test-Intermediate-CA-RSA.crt"));
        ks.setCertificateEntry("test-root-ca-ec", TestPemKeystore.getResourceCertificate("Test-Root-CA-EC.crt"));
        ks.setCertificateEntry("test-intermediate-ca-ec",
                TestPemKeystore.getResourceCertificate("Test-Intermediate-CA-EC.crt"));

        final AtomicBoolean osClosed = new AtomicBoolean(false);
        OutputStream dummyOs = new OutputStream() {

            @Override
            public void write(int b) throws IOException {
                // empty
            }

            @Override
            public void close() {
                osClosed.set(true);
            }

        };

        // no output stream needed, if supplied, it is just closed
        ks.store(dummyOs, null);

        assertTrue(osClosed.get());

        assertTrue(Files.exists(caCertsDirPath));
        assertTrue(Files.exists(caCertsDirPath.resolve("test-root-ca-rsa.crt")));
        assertTrue(Files.exists(caCertsDirPath.resolve("test-intermediate-ca-rsa.crt")));
        assertTrue(Files.exists(caCertsDirPath.resolve("test-root-ca-ec.crt")));
        assertTrue(Files.exists(caCertsDirPath.resolve("test-intermediate-ca-ec.crt")));

        Path resourcesDir = Paths.get("src/test/resources/");
        TestPemKeystore.assertFilesEqual(resourcesDir.resolve("Test-Root-CA-RSA.crt"),
                caCertsDirPath.resolve("test-root-ca-rsa.crt"));
        TestPemKeystore.assertFilesEqual(resourcesDir.resolve("Test-Intermediate-CA-RSA.crt"),
                caCertsDirPath.resolve("test-intermediate-ca-rsa.crt"));
        TestPemKeystore.assertFilesEqual(resourcesDir.resolve("Test-Root-CA-EC.crt"),
                caCertsDirPath.resolve("test-root-ca-ec.crt"));
        TestPemKeystore.assertFilesEqual(resourcesDir.resolve("Test-Intermediate-CA-EC.crt"),
                caCertsDirPath.resolve("test-intermediate-ca-ec.crt"));
    }

    @Test
    public void testCreateRsaDirectoryKeystoreWithChain() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        Path pemKeystoreDirFile = Paths.get("src/test/resources/out/keystore-dir");
        try (InputStream is = new ByteArrayInputStream(
                pemKeystoreDirFile.toString().getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }

        File certFile = new File("src/test/resources", "www.doesnotexist.org-RSA.crt");
        File caCertFile = new File("src/test/resources", "Test-Intermediate-CA-RSA.crt");
        File rootCertFile = new File("src/test/resources", "Test-Root-CA-RSA.crt");
        File keyFile = new File("src/test/resources", "www.doesnotexist.org-RSA.pem");
        String alias = "www.doesnotexist.org-RSA";

        PrivateKey privateKey = TestPemKeystore.readPrivateKey(keyFile, "RSA", null);
        X509Certificate certificate = TestPemKeystore.readCertificate(certFile);
        X509Certificate caCertificate = TestPemKeystore.readCertificate(caCertFile);
        X509Certificate rootCertificate = TestPemKeystore.readCertificate(rootCertFile);

        Certificate[] certChain = new Certificate[] { certificate, caCertificate, rootCertificate };
        ks.setKeyEntry(alias, privateKey, null, certChain);

        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            ks.store(os, null);
        }

        assertTrue(Files.exists(pemKeystoreDirFile));
        assertTrue(Files.exists(pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.crt")));
        assertTrue(Files.exists(pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.pem")));

        TestPemKeystore.assertFilesEqual(keyFile.toPath(), pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.pem"));
        assertArrayEquals(concat(certFile, caCertFile, rootCertFile),
                Files.readAllBytes(pemKeystoreDirFile.resolve("www.doesnotexist.org-RSA.crt")));
    }

    private byte[] concat(File... fileArray) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(2048);
        for (File f : fileArray) {
            buffer.write(Files.readAllBytes(f.toPath()));
        }
        return buffer.toByteArray();
    }

    private void deleteDirectory(Path toBeDeleted) throws IOException {
        if (Files.exists(toBeDeleted)) {
            Files.walk(toBeDeleted)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
    }

    @Test
    public void loadTruststoreDirectoryFromFile() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        try (InputStream is = new ByteArrayInputStream(
                "src/test/resources/dummy-file".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        assertThrowsExactly(IOException.class, () -> ks.store(null, null));
    }

    @Test
    public void loadKeystoreDirectoryWithPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        try (InputStream is = new ByteArrayInputStream(
                "src/test/resources/dir-keystore".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        Assertions.assertEquals(1, ks.size());
        String alias = "www.doesnotexist.org-EC";

        assertTrue(ks.isKeyEntry(alias));
        assertNotNull(ks.getKey(alias, null));
        Certificate[] certChain = ks.getCertificateChain(alias);
        assertNotNull(certChain);
        assertEquals(1, certChain.length);
    }

    @Test
    public void loadKeystoreDirectoryWithEncPrivateKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        String password = "password";
        try (InputStream is = new ByteArrayInputStream(
                "src/test/resources/dir-keystore-enc".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, password.toCharArray());
        }
        Assertions.assertEquals(1, ks.size());
        String alias = "www.doesnotexist.org-EC-enc";

        assertTrue(ks.isKeyEntry(alias));
        assertNotNull(ks.getKey(alias, password.toCharArray()));
        Certificate[] certChain = ks.getCertificateChain(alias);
        assertNotNull(certChain);
        assertEquals(1, certChain.length);
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
    public void testBasename() throws Exception {
        assertEquals("dummy", PemDirectoryKeystore.getFileBasename(Path.of("dummy")));
        assertEquals("dummy", PemDirectoryKeystore.getFileBasename(Path.of("dummy.crt")));
    }

    @Test
    public void loadKeystoreDecryptWrongPassword() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        String password = "password";
        String wrongPassword = "secret";
        try (InputStream is = new ByteArrayInputStream("src/test/resources/dir-keystore-enc".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, wrongPassword.toCharArray());
        }
        Assertions.assertEquals(2, ks.size());
        String alias = "www.doesnotexist.org-EC-enc";

        assertTrue(ks.isKeyEntry(alias));
        assertNotNull(ks.getKey(alias, password.toCharArray()));
        Certificate[] certChain = ks.getCertificateChain(alias);
        assertNull(certChain);
        assertNotNull(ks.getCertificate(alias));
    }

    @Test
    public void loadKeystoreSpecial() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        assertThrowsExactly(IOException.class, () -> ks.load(new ByteArrayInputStream("src/test/resources/dir-keystore-special".getBytes(StandardCharsets.UTF_8)), null));
    }

    @Test
    public void loadKeystoreUnknown() throws Exception {
        KeyStore ks = KeyStore.getInstance("pem-directory", JctProvider.getInstance());

        try (InputStream is = new ByteArrayInputStream("src/test/resources/dir-keystore-unknown".getBytes(StandardCharsets.UTF_8))) {
            ks.load(is, null);
        }
        Assertions.assertEquals(0, ks.size());
    }

}