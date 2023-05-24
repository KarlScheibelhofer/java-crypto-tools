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
 * Reeading PEM entries from a stream.
 */
class PemReader implements Closeable {

    private BufferedReader reader;

    PemReader(InputStream is) {
        reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
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
        Pem.Entry entry = new Pem.Entry(Pem.Entry.Type.unknown);
        String alias = null;

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
                case Pem.BEGIN_CERTIFICATE:  entry = new Pem.CertificateEntry(); break;
                case Pem.BEGIN_PRIVATE_KEY:  entry = new Pem.PrivateKeyEntry(); break;
                case Pem.BEGIN_ENCRYPTED_PRIVATE_KEY:  entry = new Pem.EncryptedPrivateKeyEntry(); break;
                default: entry = new Pem.UnknownEntry(line);
            }
        }

        while ((line = reader.readLine()) != null && !line.startsWith(Pem.END)) {
            sb.append(line);
        }
        String base64 = sb.toString().trim();
        if (base64.length() == 0) {
            return null;
        }
        entry.initFromEncoding(Base64.getDecoder().decode(sb.toString()));
        entry.alias = alias;
        return entry;
    }

    @Override
    public void close() throws IOException {
        this.reader.close();
    }

}
