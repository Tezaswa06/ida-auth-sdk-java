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
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
        KeyStore decryptKeyStore = loadKeyStore(encryptConfig.getDecrypt_p12_file_path(), encryptConfig.getDecrypt_p12_file_password());
        this.decryptPrivateKey = (RSAPrivateKey) decryptKeyStore.getKey("key", encryptConfig.getDecrypt_p12_file_password().toCharArray());

        // Load signing private key and certificate
        KeyStore signKeyStore = loadKeyStore(signConfig.getSign_p12_file_path(), signConfig.getSign_p12_file_password());
        String alias = "mosip"; // Replace with the correct alias if different
        char[] password = signConfig.getSign_p12_file_password().toCharArray();

        try {
            PrivateKey privateKey = (PrivateKey) signKeyStore.getKey(alias, password);

            if (privateKey == null) {
                logger.error("Private key is null. Check the alias and password.");
                logger.error("Keystore alias: " + alias);
                logger.error("Keystore password: " + signConfig.getSign_p12_file_password()); // Log the password
                throw new Exception("Private key not found in keystore");
            }

            this.signPrivateKey = (RSAPrivateKey) privateKey;
            this.signCert = (X509Certificate) signKeyStore.getCertificate(alias);

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
        } catch (Exception e) {
            logger.error("Error loading signing key: " + e.getMessage(), e);
            throw e;
        }
    }

    private static KeyStore loadKeyStore(String p12FilePath, String p12FilePassword) throws Exception {
        try (FileInputStream fis = new FileInputStream(p12FilePath)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fis, p12FilePassword.toCharArray());
            System.out.println("Keystore loaded successfully from: " + p12FilePath);
            return keyStore;
        } catch (Exception e) {
            System.err.println("Failed to load keystore. Path: " + p12FilePath + ", Error: " + e.getMessage());
            throw e;
        }
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

    private String calculateEncCertThumbprint(String certPath) throws Exception {
        X509Certificate certificate = getCertificateObj(certPath, logger);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] fingerprint = digest.digest(certificate.getEncoded());
        return Base64.encodeBase64URLSafeString(fingerprint);
    }

    public String getEncCertThumbprint() {
        return encCertThumbprint;
    }

    public static JWK getJwkPrivateKey(PrivateKey privateKey, String keyPassword, Logger logger) throws Exception {
        logger.info("Creating JWK key for JWS signing.");
        try {
            String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
                    java.util.Base64.getEncoder().encodeToString(privateKey.getEncoded()) +
                    "\n-----END PRIVATE KEY-----\n";
            return JWK.parseFromPEMEncodedObjects(privateKeyPem);
        } catch (Exception e) {
            logger.error("Error creating JWK key: " + e.getMessage());
            throw e;
        }
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

        try {
            // Generate a random AES Key
            byte[] aesKey = new byte[symmetricKeySize / 8];
            new java.security.SecureRandom().nextBytes(aesKey);

            // Encrypt Auth Request Data using the generated random key
            byte[] encryptedAuthData = symmetricEncrypt(authData, aesKey);
            String encryptedAuthDataB64 = Base64.encodeBase64URLSafeString(encryptedAuthData);
            logger.info("Generating AES Key and encrypting Auth Data Completed.");

            // Encrypt the random generated key using the IDA partner certificate
            byte[] encryptedAesKey = asymmetricEncrypt(aesKey);
            String encryptedAesKeyB64 = Base64.encodeBase64URLSafeString(encryptedAesKey);
            logger.info("Encrypting Random AES Key Completed.");

            // Generate SHA-256 hash for the Auth Request Data
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] authDataHash = digest.digest(authData);

            // Encrypt the SHA-256 hash using the AES key
            byte[] encryptedAuthDataHash = symmetricEncrypt(authDataHash, aesKey);
            String encryptedAuthDataHashB64 = Base64.encodeBase64URLSafeString(encryptedAuthDataHash);
            logger.info("Generation of SHA-256 Hash for the Auth Data completed.");

            return new String[]{encryptedAuthDataB64, encryptedAesKeyB64, encryptedAuthDataHashB64};
        } catch (Exception e) {
            logger.error("Error encrypting Auth Data. Error Message: " + e.getMessage(), e);
            throw new AuthenticatorCryptoException(Errors.AUT_CRY_003.name(), Errors.AUT_CRY_003.getMessage());
        }
    }

    public String signAuthRequestData(String authRequestData) throws Exception {
        logger.info("Request for Sign Auth Request Data.");
        try {
            // Create JWS Header with algorithm and x5c (certificate chain)
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .customParam("x5c", Collections.singletonList(
                            Base64.encodeBase64String(signCert.getEncoded())
                    ))
                    .customParam("kid", Base64.encodeBase64String(
                            MessageDigest.getInstance("SHA-256").digest(signCert.getEncoded())
                    ))
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
            logger.error("Error Signing Auth Data. Error Message: " + e.getMessage(), e);
            throw new AuthenticatorCryptoException(Errors.AUT_CRY_004.name(), Errors.AUT_CRY_004.getMessage());
        }
    }
}