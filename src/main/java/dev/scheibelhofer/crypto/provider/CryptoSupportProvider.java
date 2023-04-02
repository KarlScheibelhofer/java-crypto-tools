package dev.scheibelhofer.crypto.provider;

import java.security.Provider;

import dev.scheibelhofer.crypto.keystore.PemKeystore;

public class CryptoSupportProvider extends Provider {

    public CryptoSupportProvider() {
        super("MyProvider", "1.0",
            "Some info about my provider and which algorithms it supports");
        putService(new Provider.Service(
            this, "KeyStore", "PemKeyStore", PemKeystore.class.getName(), null, null));
    }

}
