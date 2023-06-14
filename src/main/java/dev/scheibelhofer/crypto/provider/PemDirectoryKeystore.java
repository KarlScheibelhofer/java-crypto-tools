package dev.scheibelhofer.crypto.provider;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import dev.scheibelhofer.crypto.provider.Pem.CertificateEntry;
import dev.scheibelhofer.crypto.provider.Pem.PrivateKeyEntry;

public class PemDirectoryKeystore extends PemKeystore {

    final Set<String> FILE_EXTENSIONS = Set.of(".crt", ".pem");

    private Path keystorePath;

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        if (!Files.exists(this.keystorePath)) {          
            Files.createDirectories(this.keystorePath);
        } else if (!Files.isDirectory(this.keystorePath)) {   
            throw new IOException("the provided path name during the previous call of load() must denote a directory, if it exists, it was " + this.keystorePath);
        }

        privateKeys.entrySet().stream().forEach(pke -> PemWriter.write(this.keystorePath.resolve(pke.getKey() + ".pem"), pke.getValue()));
        encryptedPrivateKeys.entrySet().stream().forEach(epke -> PemWriter.write(this.keystorePath.resolve(epke.getKey() + ".pem"), epke.getValue()));
        certificateChains.entrySet().stream().forEach(cce -> PemWriter.write(this.keystorePath.resolve(cce.getKey() + ".crt"), cce.getValue()));
        certificates.entrySet().stream().forEach(pke -> PemWriter.write(this.keystorePath.resolve(pke.getKey() + ".crt"), pke.getValue()));

        stream.close();
    }
    
    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        if (stream == null) {
            clearKeystore();
            return;
        }
        String keystoreFolderName = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        this.keystorePath = Paths.get(keystoreFolderName);

        Stream<Path> keystoreFiles;
        if (Files.isDirectory(keystorePath)) {
            keystoreFiles = Files.walk(keystorePath).filter(Files::isRegularFile);
        } else if (Files.isRegularFile(keystorePath)) {
            keystoreFiles = Stream.of(keystorePath);
        } else {
            // we just remember the keystorePath for later call to engineStore()
            keystoreFiles = Stream.empty();
        }

        List<Path> pathList = keystoreFiles
            .filter(path -> FILE_EXTENSIONS.contains(getFileExtension(path))).
            collect(Collectors.toList());

        readKeystore(pathList, password);
    }

    static String getFileExtension(Path p) {
        String name = p.getFileName().toString();
        int lastDotIndex = name.lastIndexOf(".");
        if (lastDotIndex == -1) {
            return ""; 
        }
        return name.substring(lastDotIndex);
    }

    static String getFileBasename(Path p) {
        String name = p.getFileName().toString();
        int lastDotIndex = name.lastIndexOf(".");
        if (lastDotIndex == -1) {
            return name; 
        }
        return name.substring(0, lastDotIndex);
    }

    void readKeystore(List<Path> pathList, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        List<Pem.CertificateEntry> certList = new LinkedList<>();
        for (Path filePath : pathList) {
            String aliasCandidate = getFileBasename(filePath);
            try (PemReader pemReader = new PemReader(new FileInputStream(filePath.toFile()), aliasCandidate)) {
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
                            encryptedPrivateKeys.put(makeUniqueAlias(encryptedPrivateKeys.keySet(), entry), epk);
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
            } catch (PemKeystoreException e) {
                throw new IOException("error loading key", e);
            }   
        }
        buildCertChains(certList);
        
        certList.stream().forEach(c -> certificates.put(makeUniqueAlias(certificates.keySet(), c.certificate.getSubjectX500Principal().getName()), c));
    }
}
