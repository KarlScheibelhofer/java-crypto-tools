package dev.scheibelhofer.crypto.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

public class PemKeystore extends KeyStoreSpi {

    private Map<String, Certificate> certificates = new HashMap<>();

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineGetKey'");
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineGetCertificateChain'");
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        return certificates.get(alias);
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineGetCreationDate'");
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineSetKeyEntry'");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineSetKeyEntry'");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineSetCertificateEntry'");
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineDeleteEntry'");
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(certificates.keySet());
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineContainsAlias'");
    }

    @Override
    public int engineSize() {
        return certificates.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return false;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        return certificates.containsKey(alias);
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineGetCertificateAlias'");
    }

    @Override
    public void engineStore(OutputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineStore'");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        try (stream) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");          
            Collection<? extends Certificate> certificateSet = cf.generateCertificates(stream);
            certificates = new HashMap<String,Certificate>(certificateSet.size());
            for (Certificate cer : certificateSet) {
                String alias = generateAlias(cer);
                certificates.put(alias, cer);
            }
        }                  
    }

    private String generateAlias(Certificate c) {
        String suggestedAlias;
        if (c instanceof X509Certificate) {
            X509Certificate xc = (X509Certificate) c;
            suggestedAlias = xc.getSubjectX500Principal().getName();
        } else {
            suggestedAlias = "certificate-";
        }
        return makeUniqueAlias(suggestedAlias);
    }

    private String makeUniqueAlias(String suggestedAlias) {
        String alias = suggestedAlias;
        int i = 0;
        while (certificates.containsKey(alias)) {
            alias = suggestedAlias + i;
            i++;
        }
        return alias;
    }

}