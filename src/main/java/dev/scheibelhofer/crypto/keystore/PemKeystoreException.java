package dev.scheibelhofer.crypto.keystore;

public class PemKeystoreException extends RuntimeException {

    PemKeystoreException(String message, Throwable t) {
        super(message, t);
    }
    
}
