package com.company;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {

    
    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {

        SymmetricCrypto sc = new SymmetricCrypto();
        String msg = "Hello worl";
        String en_msg = sc.encryptText(msg,sc.getSecretKey());
        String en_msg_spec = sc.encryptText(msg,sc.getSecretKeySpec());

        String de_msg = sc.decryptText(en_msg, sc.getSecretKey());
        String de_msg_spec = sc.decryptText(en_msg, sc.getSecretKeySpec());

        System.out.println("plain text " + msg);
        System.out.println("Encypted tect" + en_msg);
       System.out.println("Decrypted text" +de_msg);


    }
}
