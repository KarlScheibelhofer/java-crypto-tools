package dev.scheibelhofer.crypto.provider;

public class PemKeystoreException extends RuntimeException {

    PemKeystoreException(String message, Throwable t) {
        super(message, t);
    }
    
}
