package app;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.*;
import java.security.*;
import java.security.SecureRandom;

class app 
{
    public static void main(String[] args) throws Exception {
        String          input_text = "Hello this text is going to encrypt"; //User input text
        SecureRandom	random = new SecureRandom(); //Genrating secure random number
        IvParameterSpec ivSpec = createCtrIvForAES(1, random); 
        Key             key =   createKeyForAES(256, random); //Genrating a secure key for encryption
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC"); //Type of Encrption algorthim 
        cipher.init(Cipher.ENCRYPT_MODE, ivSpec); 

    }       
    public static SecretKey createKeyForAES(int bitLength,SecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException
    {
    KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
    
    generator.init(256, random);
    
    return generator.generateKey();
    }
    public static IvParameterSpec createCtrIvForAES(int messageNumber,SecureRandom random)
    {
        byte[]          ivBytes = new byte[16];
        
        // initially randomize
        
        random.nextBytes(ivBytes);
        ivBytes[0] = (byte)(messageNumber >> 24);
        ivBytes[1] = (byte)(messageNumber >> 16);
        ivBytes[2] = (byte)(messageNumber >> 8);
        ivBytes[3] = (byte)(messageNumber >> 0);
        
        // set the counter bytes to 1
        
        for (int i = 0; i != 7; i++)
        {
            ivBytes[8 + i] = 0;
        }
        
        ivBytes[15] = 1;
        
        return new IvParameterSpec(ivBytes);
    } 

}