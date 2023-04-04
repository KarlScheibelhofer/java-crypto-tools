package dev.scheibelhofer.crypto.keystore;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

class PemReader {

    final String BEGIN = "-----BEGIN";
    final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    final String BEGIN_ENCRYPTED_PRIVATE_KEY = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    final String END_ENCRYPTED_PRIVATE_KEY = "-----END ENCRYPTED PRIVATE KEY-----";
    final String END = "-----END";

    static class Entry {
        static enum Type {
            privateKey, x509Certificate, encryptedPrivateKey
        }
        Type type;
        byte[] encoding;
    }
    
    private BufferedReader reader;

    PemReader(InputStream is) {
        reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
    }

    List<Entry> readEntries() throws IOException {
        List<Entry> entries = new ArrayList<>();
        
        Entry entry;
        while ((entry = readEntry()) != null) {
            entries.add(entry);
        }
        
        return entries;
    }

    Entry readEntry() throws IOException {
        StringBuilder sb = new StringBuilder(1024);
        String line;
        Entry entry = new Entry();

        while ((line = reader.readLine()) != null && !line.startsWith(BEGIN));

        if (line != null) {
            switch (line) {
                case BEGIN_CERTIFICATE:  entry.type = Entry.Type.x509Certificate; break;
                case BEGIN_PRIVATE_KEY:  entry.type = Entry.Type.privateKey; break;
                case BEGIN_ENCRYPTED_PRIVATE_KEY:  entry.type = Entry.Type.encryptedPrivateKey; break;
                default: entry.type = Entry.Type.x509Certificate;
            }
        }

        while ((line = reader.readLine()) != null && !line.startsWith(END)) {
            sb.append(line);
        }
        String base64 = sb.toString().trim();
        if (base64.length() == 0) {
            return null;
        }
        entry.encoding = Base64.getDecoder().decode(sb.toString());
        return entry;
    }

}
