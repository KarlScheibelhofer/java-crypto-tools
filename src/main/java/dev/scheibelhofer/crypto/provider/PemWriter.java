package dev.scheibelhofer.crypto.provider;

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

class PemWriter implements Closeable, Flushable {

    private BufferedWriter writer;

    PemWriter(OutputStream os) {
        writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
    }

    void writeEntry(Pem.Entry entry) {
        switch (entry.type) {
            case privateKey: writePemEntry(entry.encoding, Pem.BEGIN_PRIVATE_KEY, Pem.END_PRIVATE_KEY); break;
            case encryptedPrivateKey: writePemEntry(entry.encoding, Pem.BEGIN_ENCRYPTED_PRIVATE_KEY, Pem.END_ENCRYPTED_PRIVATE_KEY); break;
            case certificate: writePemEntry(entry.encoding, Pem.BEGIN_CERTIFICATE, Pem.END_CERTIFICATE); break;
            case unknown: writePemEntry(entry.encoding, Pem.BEGIN_CERTIFICATE, Pem.END_CERTIFICATE); break;
        }
    }

    void writePemEntry(byte[] encoding, String beginLine, String endLine) {
        try {
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

}
