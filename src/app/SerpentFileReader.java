package app;

import java.security.Security;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.security.*;

class SerpentFileReader extends Thread 
{
    int counter = 0;
    static long time_second = 0;
    public static void main(String[] args) throws Exception {
        /* 
        * Generating a Secrect key which is used for encryption and decryption of File data by using Serpent.  
        */
        File file_obj = new File("D:/Input.txt");
        FileWriter file_output = new FileWriter("D:/Output.txt");
        FileInputStream fin = new FileInputStream(file_obj);

        // Storing the file data in a byte array
        byte fileContent[] = new byte[(int) file_obj.length()];
        fin.read(fileContent);
        System.out.println("Encrypted Key :" + fileContent);

        // Genrating a secrect key for encryption and decryption of file data .
        SecretKey key = generateKey();

        // Encryting a file and store in Byte Array
        byte[][] output = cbcEncrypt(key, fileContent);

        // Decrypting file data, Returns a byte array ,
        // Where the zero index consisting of iv and first index of byte array consist of cipher text.
        byte[] plainText = cbcDecrypt(key, output[0], output[1]);
        System.out.println("Decrypted Key :" + output);
        
        // Converting a decrypted byte array into plaintext 
        String plainTextString = new String(plainText);
        file_output.write(plainTextString);
        file_output.close();
        fin.close();
    }

    // Function to encrypt the file data, Returns a byte array.
    public static byte[][] cbcEncrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
        Thread u = new SerpentFileReader();
        u.start();
        Cipher cipher = Cipher.getInstance("Serpent/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };
    }

    // Function to decrypt the file data, Returns a byte array.
    public static byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("Serpent/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        System.out.println("Execution time in seconds :"+TimeUnit.MILLISECONDS.toHours(time_second));
        return cipher.doFinal(cipherText);
    }

    // Function to genrating a secrect key, returns in form of Secret Key
    public static SecretKey generateKey() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleFipsProvider());
        CryptoServicesRegistrar.setApprovedOnlyMode(false);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("Serpent", "BCFIPS");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    // Thread run method for calculating time taken for execution in milliseconds
    public void run() 
    {
        while (true) 
        {
            
        time_second = counter++;
        
        }
    }
}