package com.company;

import com.company.decrypt.DECRYPT;
import com.company.encrypt.ENCRYPT;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;


public class Main {

    public static void main(String[] args) throws NoSuchPaddingException, ShortBufferException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        System.out.println("PLEASE INPUT YOUR PASSWORD TO GENERATE A PRIVATE DES KEY");
        Scanner scanner = new Scanner(System.in);
        String input = scanner.nextLine();
        char[] password = input.toCharArray();


        ENCRYPT encrypt = new ENCRYPT(password);
        encrypt.generateDES_KEY();
        encrypt.encryptAES();
        encrypt.encryptRSA();
        DECRYPT decrypt = new DECRYPT(ENCRYPT.getMyAES(),ENCRYPT.getMyRSA(),ENCRYPT.getPrivateKey(),ENCRYPT.getSecretKeySpec(),ENCRYPT.getKeyBytes(),ENCRYPT.getCipherTXT());
        decrypt.DECRYPT_CIPHER_AES();
        decrypt.DECRYPT_CIPHER_RSA();


    }
}
