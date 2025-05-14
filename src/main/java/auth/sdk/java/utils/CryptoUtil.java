package auth.sdk.java.utils;

import auth.sdk.java.exceptions.AuthenticatorCryptoException;
import auth.sdk.java.exceptions.Errors;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

public class CryptoUtil {
    private final Logger logger;
    private final RSAPublicKey encryptPublicKey;
    private final RSAPrivateKey decryptPrivateKey;
    private final RSAPrivateKey signPrivateKey;
    private final X509Certificate signCert;
    private final String algorithm;
    private final int symmetricKeySize;
    private final int symmetricNonceSize;
    private final int symmetricGcmTagSize;
    private final String encCertThumbprint;
    private final JWK signPrivKeyJws;

    public CryptoUtil(Config.EncryptConfig encryptConfig, Config.SignConfig signConfig, Logger logger) throws Exception {
        this.logger = logger;

        // Load encryption certificate
        this.encryptPublicKey = (RSAPublicKey) getCertificateObj(encryptConfig.getEncrypt_cert_path(), logger).getPublicKey();

        // Load decryption private key
        Object[] decryptKeyStoreData = getPrivateKeyAndCertificate(
                encryptConfig.getDecrypt_p12_file_path(),
                encryptConfig.getDecrypt_p12_file_password(),
                this.logger
        );
        this.decryptPrivateKey = (RSAPrivateKey) decryptKeyStoreData[0];

        Object[] signKeyStoreData = getPrivateKeyAndCertificate(
                signConfig.getSign_p12_file_path(),
                signConfig.getSign_p12_file_password(),
                this.logger
        );
        this.signPrivateKey = (RSAPrivateKey) signKeyStoreData[0];
        this.signCert = (X509Certificate) signKeyStoreData[1];

        // Initialize signPrivKeyJws
        this.signPrivKeyJws = CryptoUtil.getJwkPrivateKey(this.signPrivateKey, signConfig.getSign_p12_file_password(), this.logger);

        // Symmetric encryption parameters
        this.symmetricKeySize = encryptConfig.getSymmetric_key_size();
        this.symmetricNonceSize = encryptConfig.getSymmetric_nonce_size() / 8;
        this.symmetricGcmTagSize = encryptConfig.getSymmetric_gcm_tag_size() / 8;

        // Calculate the thumbprint of the encryption certificate
        this.encCertThumbprint = calculateEncCertThumbprint(encryptConfig.getEncrypt_cert_path());

        // Signing algorithm
        this.algorithm = signConfig.getAlgorithm();
    }

    private static X509Certificate getCertificateObj(String certPath, Logger logger) throws AuthenticatorCryptoException {
        logger.info("Creating certificate object for the file path: {}", certPath);
        try (FileInputStream fis = new FileInputStream(certPath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(fis);
        } catch (Exception e) {
            logger.error("Error reading certificate file. Error Message: {}", e.getMessage(), e);
            throw new AuthenticatorCryptoException(Errors.AUT_CRY_001.name(), Errors.AUT_CRY_001.getMessage(certPath));
        }
    }

    public static Object[] getPrivateKeyAndCertificate(String p12FilePath, String p12FilePassword, Logger logger) throws AuthenticatorCryptoException {
        logger.info("Reading P12 file. File Path: {}", p12FilePath);
        try (FileInputStream fis = new FileInputStream(p12FilePath)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fis, p12FilePassword.toCharArray());

            String alias = keyStore.aliases().nextElement();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, p12FilePassword.toCharArray());
            Certificate certificate = keyStore.getCertificate(alias);

            return new Object[]{privateKey, certificate};
        } catch (Exception e) {
            logger.error("Error Loading P12 file to create objects. Error: {}", e.getMessage(), e);
            throw new AuthenticatorCryptoException(
                    Errors.AUT_CRY_002.name(),
                    Errors.AUT_CRY_002.getMessage(p12FilePath)
            );
        }
    }

    private String calculateEncCertThumbprint(String certPath) throws AuthenticatorCryptoException {
        logger.info("Calculating thumbprint for certificate: {}", certPath);
        try (FileInputStream fis = new FileInputStream(certPath)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(fis);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedCert = digest.digest(cert.getEncoded());
            return Base64.encodeBase64String(encodedCert);
        } catch (Exception e) {
            logger.error("Error calculating thumbprint for certificate: {}", certPath, e);
            throw new AuthenticatorCryptoException(
                    Errors.AUT_CRY_001.name(),
                    Errors.AUT_CRY_001.getMessage(certPath)
            );
        }
    }

    public static JWK getJwkPrivateKey(PrivateKey privateKey, String keyPassword, Logger logger) throws Exception {
        logger.info("Creating JWK key for JWS signing.");

        // Convert the private key to PKCS#8 format
        byte[] privateKeyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pkcs8PrivateKey = keyFactory.generatePrivate(keySpec);

        // Convert the private key to PEM format
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs8PrivateKey.getEncoded()) +
                "\n-----END PRIVATE KEY-----";

        // Create the JWK object
        return JWK.parseFromPEMEncodedObjects(privateKeyPem);
    }



    private byte[] asymmetricEncrypt(byte[] aesRandomKey) throws Exception {
        logger.debug("Encrypting the AES Random Key.");

        // Initialize RSA Cipher with OAEP padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encryptPublicKey);

        // Encrypt the AES random key
        return cipher.doFinal(aesRandomKey);
    }

    private byte[] asymmetricDecrypt(byte[] encryptedData) throws Exception {
        logger.debug("Asymmetric Decryption");

        // Initialize RSA Cipher with OAEP padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, decryptPrivateKey);

        // Decrypt the data
        return cipher.doFinal(encryptedData);
    }

    private byte[] symmetricEncrypt(byte[] data, byte[] key) throws Exception {
        logger.debug("Encrypting the Auth Data using AES Key.");

        // Generate a random IV
        byte[] iv = new byte[symmetricNonceSize];
        new java.security.SecureRandom().nextBytes(iv);

        // Initialize AES-GCM Cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(symmetricGcmTagSize * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

        // Encrypt the data
        byte[] encData = cipher.doFinal(data);

        // Combine encrypted data, tag, and IV
        byte[] tag = Arrays.copyOfRange(encData, encData.length - symmetricGcmTagSize, encData.length);
        byte[] encDataWithoutTag = Arrays.copyOfRange(encData, 0, encData.length - symmetricGcmTagSize);
        byte[] encDataFinal = new byte[encDataWithoutTag.length + tag.length + iv.length];

        System.arraycopy(encDataWithoutTag, 0, encDataFinal, 0, encDataWithoutTag.length);
        System.arraycopy(tag, 0, encDataFinal, encDataWithoutTag.length, tag.length);
        System.arraycopy(iv, 0, encDataFinal, encDataWithoutTag.length + tag.length, iv.length);

        return encDataFinal;
    }

    private byte[] symmetricDecrypt(byte[] data, byte[] key) throws Exception {
        logger.debug("Decrypting the Auth Data using AES Key.");

        // Extract IV and Tag
        int lenIv = symmetricNonceSize;
        int lenTag = symmetricGcmTagSize;
        byte[] iv = Arrays.copyOfRange(data, data.length - lenIv, data.length);
        byte[] tag = Arrays.copyOfRange(data, data.length - (lenTag + lenIv), data.length - lenIv);
        byte[] encData = Arrays.copyOfRange(data, 0, data.length - (lenTag + lenIv));

        // Combine encrypted data and tag (Java GCM expects them together)
        byte[] encDataWithTag = new byte[encData.length + tag.length];
        System.arraycopy(encData, 0, encDataWithTag, 0, encData.length);
        System.arraycopy(tag, 0, encDataWithTag, encData.length, tag.length);

        // Initialize AES-GCM Cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(lenTag * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);

        // Decrypt the data
        return cipher.doFinal(encDataWithTag);
    }

    public Map<String, Object> decryptAuthData(String sessionKeyB64, String encryptedIdentityB64) throws Exception {
        try {
            // Handle Base64 padding issues
            String sessionKeyB64Padded = Base64URL.encode(Base64URL.from(sessionKeyB64).decode()).toString();
            String encryptedIdentityB64Padded = Base64URL.encode(Base64URL.from(encryptedIdentityB64).decode()).toString();

            // Decode Base64 values
            byte[] sessionKey = Base64.decodeBase64(sessionKeyB64Padded);
            byte[] encryptedIdentity = Base64.decodeBase64(encryptedIdentityB64Padded);

            // Decrypt session key and identity
            byte[] symKey = asymmetricDecrypt(sessionKey);
            byte[] identity = symmetricDecrypt(encryptedIdentity, symKey);

            // Parse the decrypted identity as JSON
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.readValue(identity, Map.class);
        } catch (Exception e) {
            logger.error("Error decrypting Auth Data. Error Message: " + e.getMessage(), e);
            throw new AuthenticatorCryptoException(Errors.AUT_CRY_003.name(), Errors.AUT_CRY_003.getMessage());
        }
    }

    public String[] encryptAuthData(byte[] authData) throws Exception {
        logger.info("Request for Auth Data Encryption.");

        if (authData == null || authData.length == 0) {
            throw new IllegalArgumentException("Auth data cannot be null or empty");
        }

        try {
            // Generate a random AES key
            byte[] aesKey = new byte[symmetricKeySize / 8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(aesKey);

            // Encrypt the auth data using the AES key
            byte[] encryptedAuthData = symmetricEncrypt(authData, aesKey);
            String encryptedAuthB64Data = Base64.encodeBase64URLSafeString(encryptedAuthData);
            logger.info("Generating AES Key and encrypting Auth Data Completed.");

            // Encrypt the AES key using the partner's public key
            byte[] encryptedAesKey = asymmetricEncrypt(aesKey);
            String encryptedAesKeyB64 = Base64.encodeBase64URLSafeString(encryptedAesKey);
            logger.info("Encrypting Random AES Key Completed.");

            // Generate SHA-256 hash of the auth data
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] authDataHash = sha256.digest(authData);
            byte[] encAuthDataHash = symmetricEncrypt(authDataHash, aesKey);
            String encAuthDataHashB64 = Base64.encodeBase64URLSafeString(encAuthDataHash);
            logger.info("Generation of SHA256 Hash for the Auth Data completed.");

            return new String[] { encryptedAuthB64Data, encryptedAesKeyB64, encAuthDataHashB64 };
        } catch (Exception e) {
            logger.error("Error encrypting Auth Data. Error Message: {}", e.getMessage(), e);
            throw new AuthenticatorCryptoException(
                    Errors.AUT_CRY_003.name(),
                    Errors.AUT_CRY_003.getMessage()
            );
        }
    }

    public String signAuthRequestData(String authRequestData) throws Exception {
        logger.info("Request for Sign Auth Request Data.");
        try {
            // Create JWS Header with algorithm and x5c (certificate chain)
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .x509CertChain(Collections.singletonList(Base64URL.encode(signCert.getEncoded())))
                    .keyID(Base64.encodeBase64URLSafeString(signCert.getEncoded()))
                    .build();

            // Create JWS Object
            JWSObject jwsObject = new JWSObject(header, new Payload(authRequestData));

            // Sign the JWS Object
            JWSSigner signer = new RSASSASigner(signPrivateKey);
            jwsObject.sign(signer);

            // Serialize the JWS and return the compact format with ".." for the signature
            String[] jwsParts = jwsObject.serialize().split("\\.");
            logger.info("Generation for JWS Signature completed.");
            return jwsParts[0] + ".." + jwsParts[2];
        } catch (Exception e) {
            logger.error("Error Signing Auth Data. Error Message: {}", e.getMessage(), e);
            throw new AuthenticatorCryptoException(
                    Errors.AUT_CRY_004.name(),
                    Errors.AUT_CRY_004.getMessage()
            );
        }
    }

    public String getEncCertThumbprint() {
        return this.encCertThumbprint;
    }
}