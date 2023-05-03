package dev.scheibelhofer.crypto.provider;

import java.security.Provider;
import java.util.List;

/**
 * Java Crypto Tools Provider supporting PEM keystore.
 * 
 * Typical usage:
 * <code>
 * import dev.scheibelhofer.crypto.provider.CryptoSupportProvider;
 * 
 * KeyStore ks = KeyStore.getInstance("pem", CryptoSupportProvider.getInstance());
 * </code>
 */
public class JctProvider extends Provider {

    private static JctProvider prov;

    /**
     * @return a singleton instance of this provider.
     */
    public static final JctProvider getInstance() {
        if (prov == null) {
            synchronized (JctProvider.class) {
                if (prov == null) {
                    prov = new JctProvider();
                }
            }
        }
        return prov;
    }

    /** 
     * Default constructor required for JCA provider registration via class name. 
     */
    public JctProvider() {
        super("JctProvider", "1.0", "JCT Provider supporting PEM keystore");
        putService(new Provider.Service(this, "KeyStore", "pem", PemKeystore.class.getName(), null, null));
        putService(new Provider.Service(this, "AlgorithmParameters", "null", NullAlgorithmParameters.class.getName(), List.of("0.1"), null));
        putService(new Provider.Service(this, "Cipher", "null", NullCipher.class.getName(), null, null));
    }

}
