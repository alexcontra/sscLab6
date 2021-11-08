package com.company.encrypt;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class ENCRYPT {
    private static byte[] keyBytes ;
    private SecureRandom myPRNG ;
    private static SecretKeySpec myKey ;
    private static Cipher myAES;
    private static byte[] plaintextAES;
    private static byte[] cipherTextAES;
    private int cLength;
    private static String plainTXT;
    private static String cipherTXT;
    private static Cipher myRSA;
    private static KeyPairGenerator myRSAKeyGen;
    private static KeyPair myRSAKeyPair;
    private static Key pbKey ;
    private static Key pvKey ;
    private static byte[] cipherTextRSA;
    private static byte[] plainTextRSA;
    public ENCRYPT() throws NoSuchPaddingException, NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        keyBytes=new byte[16];
        myPRNG = new SecureRandom();
        myKey= new SecretKeySpec(keyBytes,"AES");
        myAES = Cipher.getInstance("AES/ECB/NoPadding");
        myRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        myAES.init(Cipher.ENCRYPT_MODE, myKey);
        myRSAKeyGen = KeyPairGenerator.getInstance("RSA");
        myRSAKeyPair =  myRSAKeyGen.generateKeyPair();
        pbKey = myRSAKeyPair.getPublic();
        pvKey = myRSAKeyPair.getPrivate();
        myRSA.init(Cipher.ENCRYPT_MODE, pbKey, myPRNG);
        myRSAKeyGen.initialize(1024, myPRNG);
        plaintextAES = new byte[16];
        cipherTextAES =new byte[16];
        plainTextRSA = new byte[16];
        cipherTextRSA =new byte[16];
        cLength =myAES.update(plaintextAES, 0, plaintextAES.length, cipherTextAES,0);
        cLength += myAES.doFinal(cipherTextAES, cLength);
    }
    public  void encryptAES(){
        System.out.println("ENCRYPTING AES!");
        plainTXT = javax.xml.bind.DatatypeConverter.printHexBinary(plaintextAES);
        cipherTXT=javax.xml.bind.DatatypeConverter.printHexBinary(cipherTextAES);
        System.out.println("plaintext:"+plainTXT);
        System.out.println("ciphertext:"+cipherTXT);
    }
    public static Cipher getMyAES(){
        return myAES;
    }
    public static Cipher getMyRSA(){
        return myRSA;
    }
    public static SecretKeySpec getSecretKeySpec(){
        return myKey;
    }
    public static Key getPrivateKey(){
        return pvKey;
    }
    public static byte[] getCipherTXT(){
        return cipherTextAES;
    }
    public static byte[] getKeyBytes(){
        return keyBytes;
    }
    public void encryptRSA() throws IllegalBlockSizeException, BadPaddingException {
        System.out.println("ENCRYPTING RSA!");
        cipherTextRSA = myRSA.doFinal(keyBytes);
        System.out.println("plaintext: "+
                javax.xml.bind.DatatypeConverter.printHexBinary(plainTextRSA));
        System.out.println("ciphertext: "+
                javax.xml.bind.DatatypeConverter.printHexBinary(cipherTextRSA));
    }
}