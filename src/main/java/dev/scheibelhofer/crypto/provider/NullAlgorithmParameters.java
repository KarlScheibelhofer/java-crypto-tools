package dev.scheibelhofer.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * Dummy AlgorithmParameters needed internally, see {@link Pem.PrivateKeyEntry#initFromEncoding(byte[])}. 
 */
public class NullAlgorithmParameters extends AlgorithmParametersSpi {

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        // empty
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        // empty
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        // empty
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        throw new UnsupportedOperationException("Unimplemented method 'engineGetParameterSpec'");
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        throw new UnsupportedOperationException("Unimplemented method 'engineGetEncoded'");
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        throw new UnsupportedOperationException("Unimplemented method 'engineGetEncoded'");
    }

    @Override
    protected String engineToString() {
        throw new UnsupportedOperationException("Unimplemented method 'engineToString'");
    }
    
}