package dev.scheibelhofer.crypto.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import dev.scheibelhofer.crypto.provider.CryptoSupportProvider;
import dev.scheibelhofer.crypto.provider.NullPrivateKey;

public class PemKeystore extends KeyStoreSpi {

    private Map<String, Certificate> certificates = new HashMap<>();
    private Map<String, PrivateKey> privateKeys = new HashMap<>();
    private Map<String, EncryptedPrivateKeyInfo> encryptedPrivateKeys = new HashMap<>();
    private Map<String, List<X509Certificate>> certificateChains = new HashMap<>();

    @Override
    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        Key k = privateKeys.get(alias);
        if (k != null) {
            return k;
        }

        EncryptedPrivateKeyInfo epki = encryptedPrivateKeys.get(alias);
        if (epki == null) {
            return null;
        }
        return decryptPrivateKey(epki, password);
    }

    private PrivateKey decryptPrivateKey(EncryptedPrivateKeyInfo epki, char[] password) throws NoSuchAlgorithmException {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
            AlgorithmParameters algParams = epki.getAlgParameters();
            // toString() yields the correct name for the cipher, not epki.getAlgName();
            String pbes2Name = algParams.toString();
            SecretKeyFactory skf = SecretKeyFactory.getInstance(pbes2Name);
            Key pbeKey = skf.generateSecret(pbeKeySpec);
            Cipher cipher = Cipher.getInstance(pbes2Name);
            cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
            PKCS8EncodedKeySpec keySpec = epki.getKeySpec(cipher);
            KeyFactory kf = KeyFactory.getInstance(keySpec.getAlgorithm());
            return kf.generatePrivate(keySpec);
        } catch (InvalidKeyException | InvalidKeySpecException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new NoSuchAlgorithmException("error decrypting private key", e);
        }
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        List<X509Certificate> certChain = certificateChains.get(alias);
        if (certChain == null) {
            return null;
        }
        return certChain.toArray(new Certificate[certChain.size()]);
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
        Set<String> aliases = new HashSet<>();
        aliases.addAll(certificates.keySet());
        aliases.addAll(privateKeys.keySet());
        aliases.addAll(encryptedPrivateKeys.keySet());
        return Collections.enumeration(aliases);
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return certificates.containsKey(alias) || privateKeys.containsKey(alias) || encryptedPrivateKeys.containsKey(alias);
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
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'engineStore'");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        try (stream) {
            PemReader pemReader = new PemReader(stream);
            Set<X509Certificate> certList = new HashSet<>();

            for (PemReader.Entry entry : pemReader.readEntries()) {
                switch (entry.type) {
                    case x509Certificate: {
                        X509Certificate cert = parseCertificate(entry.encoding);
                        certList.add(cert);
                        break;
                    }
                    case privateKey: {
                        putPrivateKey(entry);
                        break;
                    }
                    case encryptedPrivateKey: {
                        putEncryptedPrivateKey(entry, password);
                        break;
                    }
                    default:
                        break;
                }
            }
            buildCertChains(certList);
            certList.stream().forEach(c -> putCertificate(c));
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            throw new IOException("error loading key", e);
        }                  
    }

    public static boolean matching(PublicKey publicKey, PrivateKey privateKey) {
        if ((publicKey instanceof RSAPublicKey)  && (privateKey instanceof RSAPrivateKey)) {
            return matching((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);
        }
        if ((publicKey instanceof ECPublicKey)  && (privateKey instanceof ECPrivateKey)) {
            return matching((ECPublicKey) publicKey, (ECPrivateKey) privateKey);
        }
        return false;
    }

    public static boolean matching(ECPublicKey publicKey, ECPrivateKey privateKey) {
        try {
            // I found no better way using only Java standard API without additional dependency
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
     * Build certificate chains for existing private keys and remove used certificates from the list.
     * @param certList list of all certificates found in the keystore.
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    private void buildCertChains(Set<X509Certificate> certList) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (certList.isEmpty()) {
            return;
        }
        Set<X509Certificate> usedCertificates = new HashSet<>();
        for (String alias : privateKeys.keySet()) {
            PrivateKey privateKey = privateKeys.get(alias);
            List<X509Certificate> certChain = buildChainFor(privateKey, certList);
            certificateChains.put(alias, certChain);
            usedCertificates.addAll(certChain);
        }
        // avoid certificates already used in cert chains to show up as trusted certificates in addition
        certList.removeAll(usedCertificates);
    }

    static final String SUBJECT_KEY_ID = "2.5.29.14";
    static final String AUTHORITY_KEY_ID = "2.5.29.35";

    private List<X509Certificate> buildChainFor(PrivateKey privateKey, Set<X509Certificate> certList) {
        Optional<X509Certificate> privateKeyCertificate = certList.stream().filter(c -> matching(c.getPublicKey(), privateKey)).findFirst();
        List<X509Certificate> certChain = new ArrayList<>(4);
        X509Certificate cert = privateKeyCertificate.orElse(null);
        while (cert != null) {
            final X509Certificate currentCert = cert;
            // byte[] authorityKeyID = currentCert.getExtensionValue(AUTHORITY_KEY_ID);
            certChain.add(currentCert);
            cert = certList.stream()
                .filter(c -> !c.equals(currentCert))
                .filter(c -> c.getSubjectX500Principal().equals(currentCert.getIssuerX500Principal()))
                // .filter(c -> matchingKeyIDs(authorityKeyID, c))
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

        return Arrays.equals(authorityKeyID, certSubjectKeyId);
    }

    private void putEncryptedPrivateKey(PemReader.Entry entry, char[] password) throws IOException {
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(entry.encoding);
        try {
            // if keystore password is the same for encrypted private key, we decrypt it now 
            // an decrypted private key allows for certificate matching
            PrivateKey privateKey = decryptPrivateKey(epki, password);
            putPrivateKey(privateKey.getEncoded());
        } catch (Exception e) {
            String alias = makeUniqueAlias(privateKeys.keySet(), "encrypted-private-key-");
            encryptedPrivateKeys.put(alias, epki);
        }
    }

    private void putPrivateKey(PemReader.Entry entry)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException {
        putPrivateKey(entry.encoding);
    }

    private void putPrivateKey(byte[] encodedPrivateKey)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException {
        PKCS8EncodedKeySpec spec = createPkcs8KeySpec(encodedPrivateKey);
        KeyFactory kf = KeyFactory.getInstance(spec.getAlgorithm());
        PrivateKey privateKey = kf.generatePrivate(spec);
        String alias = makeUniqueAlias(privateKeys.keySet(), "private-key-");
        privateKeys.put(alias, privateKey);
    }

    private X509Certificate parseCertificate(byte[] encodedCertificate) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");         
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCertificate));
    }

    private void putCertificate(X509Certificate cert) {
        String alias = makeUniqueAlias(certificates.keySet(), cert.getSubjectX500Principal().getName());
        certificates.put(alias, cert);
    }

    private PKCS8EncodedKeySpec createPkcs8KeySpec(byte[] encoding) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException {
        // we must tweak around a litte to access the PKCS#8 decoding feature only available in EncryptedPrivateKeyInfo
        AlgorithmParameters nullAlgorithmParam = AlgorithmParameters.getInstance("0.1", CryptoSupportProvider.getInstance());
        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(nullAlgorithmParam, encoding);
        Cipher nullCipher = Cipher.getInstance("null", CryptoSupportProvider.getInstance());
        nullCipher.init(Cipher.DECRYPT_MODE, new NullPrivateKey());
        return epki.getKeySpec(nullCipher);
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