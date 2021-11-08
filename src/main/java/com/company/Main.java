package com.company;

import com.company.decrypt.DECRYPT;
import com.company.encrypt.ENCRYPT;

import javax.crypto.*;
import java.security.*;


public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        ENCRYPT encrypt = new ENCRYPT();
        encrypt.encryptAES();
        encrypt.encryptRSA();
        DECRYPT decrypt = new DECRYPT(ENCRYPT.getMyAES(),ENCRYPT.getMyRSA(),ENCRYPT.getPrivateKey(),ENCRYPT.getSecretKeySpec(),ENCRYPT.getKeyBytes(),ENCRYPT.getCipherTXT());
        decrypt.DECRYPT_CIPHER_AES();
        decrypt.DECRYPT_CIPHER_RSA();
    }
}
