package dev.scheibelhofer.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * PBES2 AlgorithmParameters needed tweaking for creating a EncryptedPrivateKeyInfo, see {@link Pem.EncryptedPrivateKeyEntry#encryptPrivateKey(char[])}. 
 */
public class PBES2AlgorithmParameters extends AlgorithmParametersSpi {

    AlgorithmParameters delegateAlgoParams;

    public PBES2AlgorithmParameters() {
        final String algParamName = "PBEWithHmacSHA256AndAES_256";
        try {
            delegateAlgoParams = AlgorithmParameters.getInstance(algParamName);
        } catch (NoSuchAlgorithmException e) {
            throw new PemKeystoreException("unsupported but required AlgorithmParameters " + algParamName, e);
        }
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        delegateAlgoParams.init(paramSpec);
    }
    
    @Override
    protected void engineInit(byte[] params) throws IOException {
        delegateAlgoParams.init(params);
    }
    
    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        delegateAlgoParams.init(params, format);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        return delegateAlgoParams.getParameterSpec(paramSpec);
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        return delegateAlgoParams.getEncoded();
    }
    
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        return delegateAlgoParams.getEncoded(format);
    }
    
    @Override
    protected String engineToString() {
        return delegateAlgoParams.toString();
    }
    
}