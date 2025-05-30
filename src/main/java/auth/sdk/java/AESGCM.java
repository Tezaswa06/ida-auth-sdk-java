package auth.sdk.java;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;
public class AESGCM {
    private static final int symmetricGcmTagSize = 128;
    private static final int symmetricNonceSize = 12; // 96 bits
    public static byte[] symmetricEncrypt(byte[] data, byte[] key, byte[] aad) throws Exception {
        System.out.println("Encrypting the Auth Data using AES Key.");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[symmetricNonceSize];
        new SecureRandom().nextBytes(iv);
        System.out.println("Generated IV:" +  Base64.getEncoder().encodeToString(iv));
        GCMParameterSpec spec = new GCMParameterSpec(symmetricGcmTagSize, iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
            System.out.println("Added AAD: {}" + Base64.getEncoder().encodeToString(aad));
        }
        byte[] encryptedData = cipher.doFinal(data);
        System.out.println("Encrypted data (including tag): {}" + Base64.getEncoder().encodeToString(encryptedData));
        byte[] output = new byte[encryptedData.length + iv.length];
        System.arraycopy(encryptedData, 0, output, 0, encryptedData.length);
        System.arraycopy(iv, 0, output, encryptedData.length, iv.length);
        System.out.println("Final encrypted output (data + IV): {}" + Base64.getEncoder().encodeToString(output));
        return output;
    }
    public static byte[] symmetricDecrypt(byte[] data, byte[] key, byte[] aad) throws Exception {
        System.out.println("Decrypting the Auth Data using AES Key.");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        int lenIv = symmetricNonceSize;
        byte[] iv = Arrays.copyOfRange(data, data.length - lenIv, data.length);
        System.out.println("Extracted IV: {}"+ Base64.getEncoder().encode(iv));
        byte[] encryptedDataWithTag = Arrays.copyOfRange(data, 0, data.length - lenIv);
        System.out.println("Encrypted data (including tag): {}"+ Base64.getEncoder().encode(encryptedDataWithTag));
        GCMParameterSpec spec = new GCMParameterSpec(symmetricGcmTagSize, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
            System.out.println("Added AAD: {}"+ Base64.getEncoder().encode(aad));
        }
        byte[] decryptedData = cipher.doFinal(encryptedDataWithTag);
        System.out.println("Decrypted data: {}" + new String(decryptedData, StandardCharsets.UTF_8));
        return decryptedData;
    }
    public static void main(String[] args) throws Exception {
        String plaintext = "This is a secret message!";
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        byte[] encData = symmetricEncrypt(data, key, null);
        System.out.println("Encrypted Data: " + Base64.getEncoder().encodeToString(encData));
        byte[] decryptedData = symmetricDecrypt(encData, key, null);
        System.out.println("Decrypted Data: " + new String(decryptedData, StandardCharsets.UTF_8));
    }
}

