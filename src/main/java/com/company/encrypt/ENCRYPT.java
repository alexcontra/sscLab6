package com.company.encrypt;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class ENCRYPT {
    private static byte[] keyBytes ;
    private SecureRandom myPRNG ;
    private static SecretKeySpec myKey ;
    private static Cipher myAES;
    private static Cipher myDES;
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
    private byte[] jump;
    private static byte[] cipherTextRSA;
    private static byte[] plainTextRSA;
    private static byte[] cipherTextDES;
    private static byte[] plainTextDES;
    private final int iteration_count;
    private final int key_size;
    private static  SecretKeyFactory keyFactory;
    private PBEKeySpec pbekSpec;
    private SecretKeySpec myAESPBKey;
    public ENCRYPT(char[] password) throws NoSuchPaddingException, NoSuchAlgorithmException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        keyBytes=new byte[16];
        myPRNG = new SecureRandom();
        myKey= new SecretKeySpec(keyBytes,"AES");
        myAES = Cipher.getInstance("AES/ECB/NoPadding");
        myRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        myDES = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        byte iv[] = myDES.getIV();
        IvParameterSpec dps = new IvParameterSpec(iv);
        myDES.init(Cipher.ENCRYPT_MODE,myAESPBKey,dps);
        myAES.init(Cipher.ENCRYPT_MODE, myKey);
        myRSAKeyGen = KeyPairGenerator.getInstance("RSA");
        myRSAKeyPair =  myRSAKeyGen.generateKeyPair();
        pbKey = myRSAKeyPair.getPublic();
        pvKey = myRSAKeyPair.getPrivate();
        myRSAKeyGen.initialize(1024, myPRNG);
        plaintextAES = new byte[16];
        cipherTextAES =new byte[16];
        plainTextRSA = new byte[16];
        cipherTextRSA =new byte[16];
        plainTextDES = new byte[16];
        cipherTextDES =new byte[16];
        jump = new byte[16];
        iteration_count = 50000;
        key_size = 128;
        myPRNG.nextBytes(jump);
        myRSA.init(Cipher.ENCRYPT_MODE, pbKey, myPRNG);
        pbekSpec = new PBEKeySpec(password, jump, iteration_count, key_size);
        keyFactory =SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        cLength =myAES.update(plaintextAES, 0, plaintextAES.length, cipherTextAES,0);
        cLength += myAES.doFinal(cipherTextAES, cLength);
    }
    public void generateDES_KEY() throws InvalidKeySpecException{
        myAESPBKey = new SecretKeySpec(keyFactory.generateSecret(pbekSpec).getEncoded(), "DES");

        System.out.println("DES key: " + javax.xml.bind.DatatypeConverter.printHexBinary(myAESPBKey.getEncoded()));
    }
    public void encryptDES() throws InvalidKeyException {
        System.out.print("ENCRYPTING DES.........\n");
        System.out.println("PLAIN TEXT: "+javax.xml.bind.DatatypeConverter.printHexBinary(plainTextDES));
        System.out.println("CIPHER TEXT:" +javax.xml.bind.DatatypeConverter.printHexBinary(cipherTextDES));
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