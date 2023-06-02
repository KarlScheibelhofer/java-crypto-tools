package dev.scheibelhofer.crypto.provider;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import dev.scheibelhofer.crypto.provider.Pem.CertificateEntry;
import dev.scheibelhofer.crypto.provider.Pem.PrivateKeyEntry;

public class FolderPemKeystore extends PemKeystore {

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException("");
                // try (final PemWriter pemOut = new PemWriter(stream)) {
        //     privateKeys.values().stream().forEach(pke -> pemOut.writeEntry(pke));
        //     encryptedPrivateKeys.values().stream().forEach(epke -> pemOut.writeEntry(epke));
        //     certificateChains.values().stream().forEach(cce -> cce.stream().forEach(c -> pemOut.writeEntry(c)));
        //     certificates.values().stream().forEach(pke -> pemOut.writeEntry(pke));
        // }
    }
    
    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        if (stream == null) {
            clearKeystore();
            return;
        }
        String keystoreFolderName = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        Path keystorePath = Paths.get(keystoreFolderName);

        Stream<Path> keystoreFiles;
        if (Files.isDirectory(keystorePath)) {
            keystoreFiles = Files.walk(keystorePath).filter(Files::isRegularFile);
        } else if (Files.isRegularFile(keystorePath)) {
            keystoreFiles = Stream.of(keystorePath);
        } else {
            throw new IOException("the specified name is neither a folder nor a regular file: " + keystoreFolderName);
        }

        keystoreFiles.forEach(file -> readKeystoreFile(file, password));
    }

    void readKeystoreFile(Path file, char[] password) {
        try {
            readKeystore(new FileInputStream(file.toFile()), password);
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new PemKeystoreException("error loading file " + file, e);
        }
    }

    void readKeystore(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        try (PemReader pemReader = new PemReader(stream)) {
            List<Pem.CertificateEntry> certList = new LinkedList<>();

            for (Pem.Entry entry : pemReader.readEntries()) {
                switch (entry.type) {
                    case certificate: {
                        certList.add((CertificateEntry) entry);
                        break;
                    }
                    case privateKey: {
                        privateKeys.put(makeUniqueAlias(privateKeys.keySet(), entry), (PrivateKeyEntry) entry);
                        break;
                    }
                    case encryptedPrivateKey: {
                        Pem.EncryptedPrivateKeyEntry epk = (Pem.EncryptedPrivateKeyEntry) entry;
                        encryptedPrivateKeys
                                .put(makeUniqueAlias(encryptedPrivateKeys.keySet(), entry), epk);
                        try {
                            epk.decryptPrivateKey(password);
                        } catch (PemKeystoreException e) {
                            // ignore at this point, the app can try later with a different password calling
                            // #engineGetKey
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
            buildCertChains(certList);

            certList.stream().forEach(c -> certificates
                    .put(makeUniqueAlias(certificates.keySet(), c.certificate.getSubjectX500Principal().getName()), c));
        } catch (PemKeystoreException | InvalidAlgorithmParameterException e) {
            throw new IOException("error loading key", e);
        }   
    }
}
