package dev.scheibelhofer.crypto.provider;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Reading PEM entries from a stream.
 */
class PemReader implements Closeable {

    private BufferedReader reader;
    private String aliasCandidate;

    PemReader(InputStream is, String aliasCandidate) {
        reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
        this.aliasCandidate = aliasCandidate;
    }

    List<Pem.Entry> readEntries() throws IOException {
        List<Pem.Entry> entries = new ArrayList<>();
        
        Pem.Entry entry;
        while ((entry = readEntry()) != null) {
            entries.add(entry);
        }
        
        return entries;
    }

    Pem.Entry readEntry() throws IOException {
        StringBuilder sb = new StringBuilder(1024);
        String line;
        Pem.Entry entry = new Pem.UnknownEntry(null, null);
        String alias = this.aliasCandidate;

        while ((line = reader.readLine()) != null && !line.startsWith(Pem.BEGIN)) {
            String trimmedLine = line.trim();
            if (trimmedLine.isEmpty()) {
                continue;
            }
            if (trimmedLine.toLowerCase(Locale.US).startsWith("alias:")) {
                alias = trimmedLine.substring(trimmedLine.indexOf(':') + 1, trimmedLine.length()).trim();
            }
        }

        if (line != null) {
            switch (line) {
                case Pem.BEGIN_CERTIFICATE:  entry = new Pem.CertificateEntry(alias); break;
                case Pem.BEGIN_PRIVATE_KEY:  entry = new Pem.PrivateKeyEntry(alias); break;
                case Pem.BEGIN_ENCRYPTED_PRIVATE_KEY:  entry = new Pem.EncryptedPrivateKeyEntry(alias); break;
            }
        }

        while ((line = reader.readLine()) != null && !line.startsWith(Pem.END)) {
            sb.append(line);
        }
        String base64 = sb.toString().trim();
        if (base64.length() == 0) {
            return null;
        }
        entry.initFromEncoding(Base64.getMimeDecoder().decode(sb.toString()));
        return entry;
    }

    @Override
    public void close() throws IOException {
        this.reader.close();
    }

}
