package dev.scheibelhofer.crypto.provider;

import java.security.Provider;
import java.util.List;

public class JctProvider extends Provider {

    public static JctProvider prov;

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

    public JctProvider() {
        super("JctProvider", "1.0", "JCT Provider supporting PEM keystore");
        putService(new Provider.Service(this, "KeyStore", "pem", PemKeystore.class.getName(), null, null));
        putService(new Provider.Service(this, "AlgorithmParameters", "null", NullAlgorithmParameters.class.getName(), List.of("0.1"), null));
        putService(new Provider.Service(this, "Cipher", "null", NullCipher.class.getName(), null, null));
    }

}
