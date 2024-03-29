package dev.scheibelhofer.crypto.provider;

/**
 * Wrapper exception to simplify exception handling using streams.
 */
public class PemKeystoreException extends RuntimeException {

    PemKeystoreException(String message, Throwable cause) {
        super(message, cause);
    }
    
}
