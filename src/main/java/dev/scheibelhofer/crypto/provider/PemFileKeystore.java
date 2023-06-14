package dev.scheibelhofer.crypto.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;

import dev.scheibelhofer.crypto.provider.Pem.CertificateEntry;
import dev.scheibelhofer.crypto.provider.Pem.PrivateKeyEntry;

public class PemFileKeystore extends PemKeystore {

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        try (final PemWriter pemOut = new PemWriter(stream, true)) {
            privateKeys.values().stream().forEach(pke -> pemOut.writeEntry(pke));
            encryptedPrivateKeys.values().stream().forEach(epke -> pemOut.writeEntry(epke));
            certificateChains.values().stream().forEach(cce -> cce.stream().forEach(c -> pemOut.writeEntry(c)));
            certificates.values().stream().forEach(pke -> pemOut.writeEntry(pke));
        }
    }
    
    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        if (stream == null) {
            clearKeystore();
            return;
        }
        try (PemReader pemReader = new PemReader(stream, null)) {
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
            buildCertChains(certList);

            certList.stream().forEach(c -> certificates
                    .put(makeUniqueAlias(certificates.keySet(), c.certificate.getSubjectX500Principal().getName()), c));
        } catch (PemKeystoreException e) {
            throw new IOException("error loading key", e);
        }
    }    
}
