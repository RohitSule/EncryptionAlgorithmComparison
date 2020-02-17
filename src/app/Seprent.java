package app;

import java.security.Security;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.security.*;

class Serpent extends Thread 
{
    int counter = 0;
    static long time_second = 0;
    public static void main(String[] args) throws Exception 
    {
        String user_input = "Hello";
        byte[] value = user_input.getBytes();
        System.out.println("Encrypted Key :"+value);
        SecretKey key = generateKey();
        byte[][] output = cbcEncrypt(key, value);
        byte[] plainText = cbcDecrypt(key, output[0], output[1]);
        System.out.println("Decrypted Key :"+output);
        String plainTextString = new String(plainText);
        System.out.println("Plain Text given by user :"+plainTextString);
    }

    public static byte[][] cbcEncrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        Thread u = new Serpent();
        u.start();
        Cipher cipher = Cipher.getInstance("Serpent/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };
    }

    public static byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("Serpent/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        System.out.println("Execution time in seconds :"+TimeUnit.MILLISECONDS.toHours(time_second));
        return cipher.doFinal(cipherText);
    }

    public static SecretKey generateKey() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleFipsProvider());
        CryptoServicesRegistrar.setApprovedOnlyMode(false);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Serpent", "BCFIPS");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
    public void run() 
    {
        while (true) 
        {
            
        time_second = counter++;
        
        }
    }
}