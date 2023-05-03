package dev.scheibelhofer.crypto.provider;

import java.security.PrivateKey;

/**
 * Dummy PrivateKey needed internally, see {@link Pem.PrivateKeyEntry#initFromEncoding(byte[])}. 
 */
public class NullPrivateKey implements PrivateKey {

    @Override
    public String getAlgorithm() {
        return "null";
    }
    
    @Override
    public String getFormat() {
        return "null";
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
    
}
