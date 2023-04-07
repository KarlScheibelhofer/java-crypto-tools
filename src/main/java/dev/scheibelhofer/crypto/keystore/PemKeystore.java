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
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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
        return decrypPrivateKeyJDK(epki, password);
    }

    private PrivateKey decrypPrivateKeyJDK(EncryptedPrivateKeyInfo epki, char[] password) throws NoSuchAlgorithmException {
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

            for (PemReader.Entry entry : pemReader.readEntries()) {
                switch (entry.type) {
                    case x509Certificate: {
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");         
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(entry.encoding));
                        String alias = makeUniqueAlias(certificates.keySet(), cert.getSubjectX500Principal().getName());
                        certificates.put(alias, cert);
                        break;
                    }
                    case privateKey: {
                        PKCS8EncodedKeySpec spec = createPkcs8KeySpec(entry.encoding);
                        KeyFactory kf = KeyFactory.getInstance(spec.getAlgorithm());
                        PrivateKey privateKey = kf.generatePrivate(spec);
                        String alias = makeUniqueAlias(privateKeys.keySet(), "private-key-");
                        privateKeys.put(alias, privateKey);
                        break;
                    }
                    case encryptedPrivateKey: {
                        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(entry.encoding);
                        String alias = makeUniqueAlias(privateKeys.keySet(), "encrypted-private-key-");
                        encryptedPrivateKeys.put(alias, epki);
                        break;
                    }
                    default:
                        break;
                }
            }
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException e) {
            throw new IOException("error loading key", e);
        }                  
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