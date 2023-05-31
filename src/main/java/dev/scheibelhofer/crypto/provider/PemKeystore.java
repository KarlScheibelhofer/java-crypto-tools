package dev.scheibelhofer.crypto.provider;

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
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.security.auth.x500.X500Principal;

import dev.scheibelhofer.crypto.provider.Pem.CertificateEntry;
import dev.scheibelhofer.crypto.provider.Pem.PrivateKeyEntry;

/**
 * KeyStore implementation for reading PEM format private keys and certificates.
 */
public abstract class PemKeystore extends KeyStoreSpi {

    final Map<String, Pem.PrivateKeyEntry> privateKeys = new LinkedHashMap<>();
    final Map<String, Pem.EncryptedPrivateKeyEntry> encryptedPrivateKeys = new LinkedHashMap<>();
    final Map<String, List<Pem.CertificateEntry>> certificateChains = new LinkedHashMap<>();
    final Map<String, Pem.CertificateEntry> certificates = new LinkedHashMap<>();
    final Date creationDate = new Date();

    void clearKeystore() {
        privateKeys.clear();
        encryptedPrivateKeys.clear();
        certificateChains.clear();
        certificates.clear();
    }

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
        return this.creationDate;
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException {
        if (key instanceof PrivateKey) {
            if (password == null) {
                PrivateKeyEntry keyEntry = new Pem.PrivateKeyEntry(alias, (PrivateKey) key);
                privateKeys.put(alias, keyEntry);
                List<Pem.CertificateEntry> certificateChain = Stream.of(chain)
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .map(c -> new Pem.CertificateEntry(alias, c))
                    .collect(Collectors.toList());
                certificateChains.put(alias, certificateChain);
            }
        }
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] encryptedKey, Certificate[] chain) throws KeyStoreException {
        Pem.EncryptedPrivateKeyEntry encryptedKeyEntry = new Pem.EncryptedPrivateKeyEntry(alias);
        encryptedKeyEntry.initFromEncoding(encryptedKey);
        encryptedPrivateKeys.put(alias, encryptedKeyEntry);
        List<Pem.CertificateEntry> certificateChain = Stream.of(chain)
            .filter(X509Certificate.class::isInstance)
            .map(X509Certificate.class::cast)
            .map(c -> new Pem.CertificateEntry(alias, c))
            .collect(Collectors.toList());
        certificateChains.put(alias, certificateChain);
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        if (!(cert instanceof X509Certificate)) {
            throw new KeyStoreException("certificate entry must be of type java.security.cert.X509Certificate, but is " + cert.getClass());
        }
        X509Certificate x509Cert = (X509Certificate) cert;
        Pem.CertificateEntry certEntry = new Pem.CertificateEntry(alias, x509Cert);
        certificates.put(alias, certEntry);
    }

    @Override
    public void engineDeleteEntry(String alias) throws KeyStoreException {
        encryptedPrivateKeys.remove(alias);
        privateKeys.remove(alias);
        certificateChains.remove(alias);
        certificates.remove(alias);
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
        if (cert == null) {
            return null;
        }
        for (Entry<String, CertificateEntry> entry : certificates.entrySet()) {
            if (cert.equals(entry.getValue().certificate)) {
                return entry.getKey();
            }
        }
        for (Entry<String, List<CertificateEntry>> entry : certificateChains.entrySet()) {
            List<CertificateEntry> chain = entry.getValue();
            if (chain.size() == 0) {
                continue;
            }
            CertificateEntry firstCertChainEntry = chain.get(0);
            if (cert.equals(firstCertChainEntry.certificate)) {
                return entry.getKey();
            }
        }
        return null;
    }

    static boolean matching(PublicKey publicKey, PrivateKey privateKey) {
        if ((publicKey instanceof RSAPublicKey) && (privateKey instanceof RSAPrivateKey)) {
            return matching((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
        }
        if ((publicKey instanceof ECPublicKey) && (privateKey instanceof ECPrivateKey)) {
            return matching((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
        }
        return false;
    }

    static boolean matching(ECPublicKey publicKey, ECPrivateKey privateKey) {
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

    static boolean matching(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
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
    void buildCertChains(List<Pem.CertificateEntry> certList)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (certList.isEmpty()) {
            return;
        }
        Set<Pem.CertificateEntry> usedCertificates = new HashSet<>();
        for (String alias : privateKeys.keySet()) {
            Pem.PrivateKeyEntry privateKeyEntry = privateKeys.get(alias);
            List<Pem.CertificateEntry> certChain = buildChainFor(privateKeyEntry, certList);
            if (certChain.size() > 0) {
                String newAlias;
                if (privateKeyEntry.alias != null) {
                    newAlias = alias;
                } else {
                    newAlias = makeAlias(certChain.get(0));
                    privateKeys.remove(alias);
                    privateKeys.put(newAlias, privateKeyEntry);
                }
                certificateChains.put(newAlias, certChain);
                usedCertificates.addAll(certChain);
            }
        }
        // avoid certificates already used in cert chains to show up as trusted
        // certificates in addition
        certList.removeAll(usedCertificates);
    }

    String makeAlias(CertificateEntry certificateEntry) {
        X500Principal subject = certificateEntry.certificate.getSubjectX500Principal();
        return subject.getName();
    }

    static final String SUBJECT_KEY_ID = "2.5.29.14";
    static final String AUTHORITY_KEY_ID = "2.5.29.35";

    List<Pem.CertificateEntry> buildChainFor(Pem.PrivateKeyEntry privateKeyEntry,
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

    static boolean matchingKeyIDs(byte[] authorityKeyID, X509Certificate c) {
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

    String makeUniqueAlias(Set<String> existingAliases, String suggestedAlias) {
        String alias = suggestedAlias;
        int i = 2;
        while (existingAliases.contains(alias)) {
            alias = suggestedAlias + "-" + i;
            i++;
        }
        return alias;
    }

    String makeUniqueAlias(Set<String> aliasSet, Pem.Entry entry) {
        if (entry.alias != null) {
            return makeUniqueAlias(aliasSet, entry.alias);
        }
        if (entry instanceof Pem.PrivateKeyEntry) {
            return makeUniqueAlias(aliasSet, "private-key");
        } else if (entry instanceof Pem.EncryptedPrivateKeyEntry) {
            return makeUniqueAlias(aliasSet, "encrypted-private-key");
        } 
        return makeUniqueAlias(aliasSet, "entry");
    }

}