package dev.scheibelhofer.crypto.provider;

import java.security.Provider;
import java.security.Security;

public class ProviderCheck {
    public static void main(String[] args) throws Exception {
        for (Provider provider : Security.getProviders()) {
            System.out.println("##########################################################################");
            System.out.println("Provider: "  + provider.getName());
            for (Object k: provider.keySet()) {
                String key = (String) k;
                if (key.toLowerCase().startsWith("alg.alias")) {
                    String alias = key;
                    String algName = provider.getProperty(alias);
                    System.out.println(alias + " -> " + algName);
                }
            }
        }
    }
    
}
