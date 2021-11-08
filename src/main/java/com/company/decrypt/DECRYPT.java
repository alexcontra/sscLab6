package com.company.decrypt;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class DECRYPT {
    private Cipher myAES;
    private Cipher myRSA;
    private byte[] keyBytes;
    private Key pvKey;
    private SecretKeySpec myKey;
    private static byte[] dec_plaintext ;
    private int cLength;
    private byte[] cipher;
    public DECRYPT(Cipher myAES,Cipher myRSA,Key pvKey,SecretKeySpec myKey,byte[] keyBytes,byte[] ciphertext) throws InvalidKeyException, ShortBufferException {
        this.myAES=myAES;
        this.myKey=myKey;
        this.myRSA = myRSA;
        this.pvKey = pvKey;
        this.keyBytes=keyBytes;
        dec_plaintext = new byte[16];
        myAES.init(Cipher.DECRYPT_MODE, myKey);
        myRSA.init(Cipher.DECRYPT_MODE, pvKey);
        this.cipher= ciphertext;
        cLength = myAES.update(cipher, 0, cipher.length, dec_plaintext,
                0);
    }
    public  void DECRYPT_CIPHER_AES() throws IllegalBlockSizeException, ShortBufferException, BadPaddingException {
        System.out.println("DECRYPTING AES........\n");
        System.out.println("decrypted:"+javax.xml.bind.DatatypeConverter.printHexBinary(dec_plaintext));
        cLength += myAES.doFinal(dec_plaintext, cLength);
    }
    public void DECRYPT_CIPHER_RSA(){
        System.out.println("GETTING KEYBYTES........\n");
        System.out.println("keybytes: "+
                javax.xml.bind.DatatypeConverter.printHexBinary(keyBytes));
    }
}