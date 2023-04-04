package dev.scheibelhofer.crypto.provider;

import java.security.Provider;
import java.util.List;

import dev.scheibelhofer.crypto.keystore.PemKeystore;

public class CryptoSupportProvider extends Provider {

    public static CryptoSupportProvider prov;

    public static final CryptoSupportProvider getInstance() {
        if (prov == null) {
            synchronized (CryptoSupportProvider.class) {
                if (prov == null) {
                    prov = new CryptoSupportProvider();
                }
            }
        }
        return prov;
    }

    public CryptoSupportProvider() {
        super("MyProvider", "1.0",
            "Some info about my provider and which algorithms it supports");
        putService(new Provider.Service(this, "KeyStore", "PemKeyStore", PemKeystore.class.getName(), null, null));
        putService(new Provider.Service(this, "AlgorithmParameters", "null", NullAlgorithmParameters.class.getName(), List.of("0.1"), null));
        putService(new Provider.Service(this, "Cipher", "null", NullCipher.class.getName(), null, null));
    }

}
