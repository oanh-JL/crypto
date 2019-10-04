package com.company;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SymmetricCrypto {

    private final String algorithm = "AES";

    private KeyGenerator keyGenerator;

    private SecretKey secretKey;

    private SecretKeySpec secretKeySpec;

    private Cipher cipher;

    public SymmetricCrypto() throws NoSuchAlgorithmException {

        keyGenerator = KeyGenerator.getInstance(algorithm);

        secretKey = keyGenerator.generateKey();

        /**
         * @param key = 16 ki tu
         */
        String key = "abcdefghiklmnopq";
        secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
    }

    /**
     * ma hoa
     *
     * @param msg
     * @param key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     */
    public String encryptText(String msg, SecretKey key) throws NoSuchAlgorithmException,
            InvalidKeyException, UnsupportedEncodingException,
            IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
        cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));
    }

    public String encryptText1(String msg, SecretKeySpec key) throws UnsupportedEncodingException,
            BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {
        cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));
    }

    /**
     * giai ma
     *
     * @param msg
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     */

    public String decryptText(String msg, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new String(cipher.doFinal(Base64.getDecoder().decode(msg)), "UTF-8");
    }

    public String decryptTextSpec (String msg, SecretKeySpec key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return  new String(cipher.doFinal(Base64.getDecoder().decode(msg)), "UTF-8");
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public SecretKeySpec getSecretKeySpec() {
        return secretKeySpec;
    }
}
