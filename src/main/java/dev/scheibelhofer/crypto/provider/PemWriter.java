package dev.scheibelhofer.crypto.provider;

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.Flushable;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

import dev.scheibelhofer.crypto.provider.Pem.CertificateEntry;

/**
 * Writing PEM entries to a stream.
 */
class PemWriter implements Closeable, Flushable {

    private BufferedWriter writer;
    private boolean writeAliasLine;

    PemWriter(OutputStream os, boolean writeAliasLine) {
        writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
        this.writeAliasLine = writeAliasLine;
    }

    void writeEntry(Pem.Entry entry) {
        switch (entry.type) {
            case privateKey: writePemEntry(entry.alias, entry.encoding, Pem.BEGIN_PRIVATE_KEY, Pem.END_PRIVATE_KEY); break;
            case encryptedPrivateKey: writePemEntry(entry.alias, entry.encoding, Pem.BEGIN_ENCRYPTED_PRIVATE_KEY, Pem.END_ENCRYPTED_PRIVATE_KEY); break;
            case certificate: writePemEntry(entry.alias, entry.encoding, Pem.BEGIN_CERTIFICATE, Pem.END_CERTIFICATE); break;
            case unknown: writePemEntry(entry.alias, entry.encoding, Pem.BEGIN_CERTIFICATE, Pem.END_CERTIFICATE); break;
        }
    }

    void writePemEntry(String alias, byte[] encoding, String beginLine, String endLine) {
        try {
            if (writeAliasLine && alias != null) {
                writer.write("Alias: ");
                writer.write(alias);
                writer.write("\n");
            }
            writer.write(beginLine);
            writer.write("\n");
            writer.write(Base64.getMimeEncoder(64, new byte[] { 0x0a}).encodeToString(encoding));
            writer.write("\n");
            writer.write(endLine);
            writer.write("\n");
        } catch (IOException e) {
            throw new PemKeystoreException("failed writing PEM entry", e);
        }
    }

    @Override
    public void close() throws IOException {
        this.writer.close();
    }

    @Override
    public void flush() throws IOException {
        this.writer.flush();
    }

    public static void write(Path filePath, Pem.Entry entry){
        try (PemWriter pw = new PemWriter(new FileOutputStream(filePath.toFile()), false)) {
            pw.writeEntry(entry);;
        } catch (IOException e) {
            throw new PemKeystoreException("failed writing PEM entry to file " + filePath, e);
        }
    }

    public static void write(Path filePath, List<CertificateEntry> certificateChainEntries) {
        try (PemWriter pw = new PemWriter(new FileOutputStream(filePath.toFile()), false)) {
            certificateChainEntries.stream().forEach(c -> pw.writeEntry(c));
        } catch (IOException e) {
            throw new PemKeystoreException("failed writing PEM entry to file " + filePath, e);
        }
    }

}
