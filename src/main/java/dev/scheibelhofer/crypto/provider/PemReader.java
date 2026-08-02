package dev.scheibelhofer.crypto.provider;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.DEREncodable;
import java.security.KeyPair;
import java.security.PEM;
import java.security.PEMDecoder;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import javax.crypto.EncryptedPrivateKeyInfo;

/**
 * Reading PEM entries from a stream.
 */
class PemReader implements Closeable {

    private final InputStream is;
    private final String aliasCandidate;

    PemReader(InputStream is, String aliasCandidate) {
        this.is = is;
        this.aliasCandidate = aliasCandidate;
    }

    List<Pem.Entry> readEntries() throws IOException {
        List<Pem.Entry> entries = new ArrayList<>();
        
        try {
            Pem.Entry entry;
            while ((entry = readEntry()) != null) {
                entries.add(entry);
            }
        } catch (EOFException eofEx) {
            // end of stream reached, that's fine
        }
        
        return entries;
    }

    Pem.Entry readEntry() throws IOException {
        String alias = this.aliasCandidate;

        // first read as PEM to be be able to get the alias if present
        // leadingData() is only available for generic PEM
        PEM pem = PEMDecoder.of().decode(is, PEM.class);
        String pemHeaderAlias = extractAliasFromLeadingData(pem.leadingData());
        if (pemHeaderAlias != null) {
            alias = pemHeaderAlias;   
        }

        // now read PEM to key or certificate
        DEREncodable decodedPem = PEMDecoder.of().decode(pem.toString());
        return switch (decodedPem) {
            case X509Certificate cert -> new Pem.CertificateEntry(alias, cert);
            case PrivateKey privateKey -> new Pem.PrivateKeyEntry(alias, privateKey);
            case KeyPair keyPair -> new Pem.PrivateKeyEntry(alias, keyPair.getPrivate());
            case EncryptedPrivateKeyInfo encryptedPrivateKeyInfo -> new Pem.EncryptedPrivateKeyEntry(alias, encryptedPrivateKeyInfo);
            default -> new Pem.UnknownEntry(alias, pem.type());
        };
    }

    private String extractAliasFromLeadingData(byte[] leadingData) {
        if (leadingData == null) {
            return null;
        }
        String leadingText = new String(leadingData, StandardCharsets.UTF_8);
        for (String line : leadingText.split("\\r?\\n")) {
            String trimmedLine = line.trim();
            if (trimmedLine.toLowerCase(Locale.US).startsWith("alias:")) {
                return trimmedLine.substring(trimmedLine.indexOf(':') + 1).trim();
            }
        }
        return null;
    }

    @Override
    public void close() throws IOException {
        this.is.close();
    }

}
