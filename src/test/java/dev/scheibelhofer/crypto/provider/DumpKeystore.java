package dev.scheibelhofer.crypto.provider;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class DumpKeystore {

    public static void main(String[] args) throws Exception {
        KeyStore ks = KeyStore.getInstance("pem", JctProvider.getInstance());
        char[] password = null;
        ks.load(new FileInputStream("src/test/resources/www.doesnotexist.org-EC-keystore.pem"), password);

        Enumeration<String> aliasEnum = ks.aliases();
        while (aliasEnum.hasMoreElements()) {
            String alias = aliasEnum.nextElement();
            if (ks.isCertificateEntry(alias)) {
                Certificate c = ks.getCertificate(alias);
                System.out.println("certificate entry with alias: " + alias);
                System.out.println(c);
            }
            if (ks.isKeyEntry(alias)) {
                Key k = ks.getKey(alias, password);
                System.out.println("key entry with alias: " + alias);
                System.out.println("key algorithm: " + k.getAlgorithm());
                Certificate[] chain = ks.getCertificateChain(alias);
                System.out.println("certificate chain with " + chain.length + " certificates");
                for (int i = 0; i < chain.length; i++) {
                    System.out.println("certificate [" + i + "]:");
                    System.out.println(chain[i]);
                    
                }

            }
        }

    }
    
}
