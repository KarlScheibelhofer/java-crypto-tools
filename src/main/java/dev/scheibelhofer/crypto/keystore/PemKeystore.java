package dev.scheibelhofer.crypto.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.security.auth.x500.X500Principal;

import dev.scheibelhofer.crypto.keystore.Pem.CertificateEntry;
import dev.scheibelhofer.crypto.keystore.Pem.PrivateKeyEntry;

public class PemKeystore extends KeyStoreSpi {

    private Map<String, Pem.PrivateKeyEntry> privateKeys = new LinkedHashMap<>();
    private Map<String, Pem.EncryptedPrivateKeyEntry> encryptedPrivateKeys = new LinkedHashMap<>();
    private Map<String, List<Pem.CertificateEntry>> certificateChains = new LinkedHashMap<>();
    private Map<String, Pem.CertificateEntry> certificates = new LinkedHashMap<>();

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        Pem.PrivateKeyEntry privateKeyEntry = privateKeys.get(alias);
        if (privateKeyEntry != null) {
            return privateKeyEntry.privateKey;
        }

        Pem.EncryptedPrivateKeyEntry encryptedPrivateKeyEntry = encryptedPrivateKeys.get(alias);
        if (encryptedPrivateKeyEntry == null) {
            return null;
        }
        try {
            encryptedPrivateKeyEntry.decryptPrivateKey(password);
            return encryptedPrivateKeyEntry.privateKey;
        } catch (PemKeystoreException e) {
            throw new NoSuchAlgorithmException("failed decrypting encrypted private key", e);

        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        List<Pem.CertificateEntry> certEntries = certificateChains.get(alias);
        if (certEntries == null) {
            return null;
        }
        return certEntries.stream().map(ce -> ce.certificate).collect(Collectors.toList())
                .toArray(new Certificate[certEntries.size()]);
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        Pem.CertificateEntry ce = certificates.get(alias);
        if (ce == null) {
            return null;
        }
        return ce.certificate;
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
        Set<String> aliases = new HashSet<>();
        aliases.addAll(certificates.keySet());
        aliases.addAll(privateKeys.keySet());
        aliases.addAll(encryptedPrivateKeys.keySet());
        return Collections.enumeration(aliases);
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return certificates.containsKey(alias) || privateKeys.containsKey(alias)
                || encryptedPrivateKeys.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return certificates.size() + privateKeys.size() + encryptedPrivateKeys.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        return privateKeys.containsKey(alias) || encryptedPrivateKeys.containsKey(alias);
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
        try (final PemWriter pemOut = new PemWriter(stream)) {
            privateKeys.values().stream().forEach(pke -> pemOut.writeEntry(pke));
            encryptedPrivateKeys.values().stream().forEach(epke -> pemOut.writeEntry(epke));
            certificateChains.values().stream().forEach(cce -> cce.stream().forEach(c -> pemOut.writeEntry(c)));
            certificates.values().stream().forEach(pke -> pemOut.writeEntry(pke));
        }
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        try (PemReader pemReader = new PemReader(stream)) {
            List<Pem.CertificateEntry> certList = new LinkedList<>();

            for (Pem.Entry entry : pemReader.readEntries()) {
                switch (entry.type) {
                    case certificate: {
                        certList.add((CertificateEntry) entry);
                        break;
                    }
                    case privateKey: {
                        privateKeys.put(makeUniqueAlias(privateKeys.keySet(), "private-key-"), (PrivateKeyEntry) entry);
                        break;
                    }
                    case encryptedPrivateKey: {
                        Pem.EncryptedPrivateKeyEntry epk = (Pem.EncryptedPrivateKeyEntry) entry;
                        encryptedPrivateKeys
                                .put(makeUniqueAlias(encryptedPrivateKeys.keySet(), "encrypted-private-key-"), epk);
                        try {
                            epk.decryptPrivateKey(password);
                        } catch (PemKeystoreException e) {
                            // ignore at this point, the app can try later with a different password calling
                            // #engineGetKey
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
            buildCertChains(certList);

            certList.stream().forEach(c -> certificates
                    .put(makeUniqueAlias(certificates.keySet(), c.certificate.getSubjectX500Principal().getName()), c));
        } catch (PemKeystoreException | InvalidAlgorithmParameterException e) {
            throw new IOException("error loading key", e);
        }
    }

    public static boolean matching(PublicKey publicKey, PrivateKey privateKey) {
        if ((publicKey instanceof RSAPublicKey) && (privateKey instanceof RSAPrivateKey)) {
            return matching((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
        }
        if ((publicKey instanceof ECPublicKey) && (privateKey instanceof ECPrivateKey)) {
            return matching((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
        }
        return false;
    }

    public static boolean matching(ECPublicKey publicKey, ECPrivateKey privateKey) {
        try {
            // I found no better way using only Java standard API without additional
            // dependency
            byte[] data = new byte[32];
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(privateKey);
            s.update(data);
            byte[] sig = s.sign();
            s.initVerify(publicKey);
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean matching(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        return publicKey.getModulus().equals(privateKey.getModulus());
    }

    /**
     * Build certificate chains for existing private keys and remove used
     * certificates from the list.
     * 
     * @param certList list of all certificates found in the keystore.
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    private void buildCertChains(List<Pem.CertificateEntry> certList)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (certList.isEmpty()) {
            return;
        }
        Set<Pem.CertificateEntry> usedCertificates = new HashSet<>();
        for (String alias : privateKeys.keySet()) {
            Pem.PrivateKeyEntry privateKeyEntry = privateKeys.get(alias);
            List<Pem.CertificateEntry> certChain = buildChainFor(privateKeyEntry, certList);
            if (certChain.size() > 0) {
                String newAlias = makeAlias(certChain.get(0));
                privateKeys.remove(alias);
                privateKeys.put(newAlias, privateKeyEntry);
                certificateChains.put(newAlias, certChain);
                usedCertificates.addAll(certChain);
            }
        }
        // avoid certificates already used in cert chains to show up as trusted
        // certificates in addition
        certList.removeAll(usedCertificates);
    }

    private String makeAlias(CertificateEntry certificateEntry) {
        X500Principal subject = certificateEntry.certificate.getSubjectX500Principal();
        return subject.getName();
    }

    static final String SUBJECT_KEY_ID = "2.5.29.14";
    static final String AUTHORITY_KEY_ID = "2.5.29.35";

    private List<Pem.CertificateEntry> buildChainFor(Pem.PrivateKeyEntry privateKeyEntry,
            List<Pem.CertificateEntry> certList) {
        Optional<Pem.CertificateEntry> privateKeyCertificate = certList.stream()
                .filter(c -> matching(c.certificate.getPublicKey(), privateKeyEntry.privateKey)).findFirst();
        List<Pem.CertificateEntry> certChain = new ArrayList<>(4);
        Pem.CertificateEntry cert = privateKeyCertificate.orElse(null);
        while (cert != null) {
            final Pem.CertificateEntry currentCertEntry = cert;
            byte[] authorityKeyID = currentCertEntry.certificate.getExtensionValue(AUTHORITY_KEY_ID);
            certChain.add(currentCertEntry);
            cert = certList.stream()
                    .filter(ce -> !ce.equals(currentCertEntry))
                    .filter(ce -> ce.certificate.getSubjectX500Principal()
                            .equals(currentCertEntry.certificate.getIssuerX500Principal()))
                    .filter(ce -> matchingKeyIDs(authorityKeyID, ce.certificate))
                    .findFirst().orElse(null);
        }
        return certChain;
    }

    public static boolean matchingKeyIDs(byte[] authorityKeyID, X509Certificate c) {
        if (authorityKeyID == null) {
            return true;
        }
        byte[] certSubjectKeyId = c.getExtensionValue(SUBJECT_KEY_ID);
        if (certSubjectKeyId == null) {
            return true;
        }

        // check that trailing 20 bytes (sha1) match
        return Arrays.equals(authorityKeyID, authorityKeyID.length - 20, authorityKeyID.length, certSubjectKeyId,
                certSubjectKeyId.length - 20, certSubjectKeyId.length);
    }

    private String makeUniqueAlias(Set<String> existingAliases, String suggestedAlias) {
        String alias = suggestedAlias;
        int i = 0;
        while (existingAliases.contains(alias)) {
            alias = suggestedAlias + i;
            i++;
        }
        return alias;
    }

}