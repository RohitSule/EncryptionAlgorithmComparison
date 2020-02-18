package app;

import java.util.concurrent.TimeUnit;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import java.security.*;

class Ecdsa extends Thread {
    int counter = 0;
    static long time_second = 0;

    public static void main(String[] args) throws Exception {
         /* 
        * Generating a key-pair out of email to visualize a scenario where email
        * is used as a authenticity mechanism to validate a request using ECDSA. 
        * E.g.: Yash sends a request to Dhananjay's Computer to update the git
        database hosted on his computer.
        */
        String user_input = "Yash_dave@gmail.com";

        // Converting to Byte Array for encryption 
        byte[] value = user_input.getBytes();
        System.out.println("Input Array:" + value);

        // Genrating a Public - Private key pair
        KeyPair key = generateKeyPair();
        PrivateKey private_key = key.getPrivate();
        System.out.println("Private key :" + private_key);

        // Genrates a Signatiure by using Private key 
        byte[] sign = generateSignature(private_key, value);
        System.out.println("Signature :" + sign);
        PublicKey public_key = key.getPublic();
        System.out.println("Public key :" + public_key);

        // Verifying the Signature using public key
        Boolean check = verifySignature(public_key, value, sign);
        if (check == true) {
            System.out.println("Verified");
        } else {
            System.out.println("Not verified");
        }
    }

    // Function for KeyPair Generation, Returns a KeyPair Object which contains
    // public and private keys
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleFipsProvider());
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BCFIPS");
        keyPair.initialize(384);
        return keyPair.generateKeyPair();
    }

    // Function for GeneratingSignature, Returns Encrypted Signature  
    // in Byte Array    
    public static byte[] generateSignature(PrivateKey ecPrivate, byte[] input) throws GeneralSecurityException {
        Thread u = new Ecdsa();
        u.start();
        Signature signature = Signature.getInstance("SHA384withECDSA", "BCFIPS");
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    // Function to verifySignature, Returns a Boolean 
    // To check wheather it is authencticated or not    
    public static boolean verifySignature(PublicKey ecPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA384withECDSA", "BCFIPS");
        signature.initVerify(ecPublic);
        signature.update(input);
        System.out.println("Execution time in seconds :" + TimeUnit.MILLISECONDS.toHours(time_second));
        return signature.verify(encSignature);
    }
    
    // Thread run method for calculating time taken for execution in milliseconds
    public void run() {
        while (true) {

            time_second = counter++;

        }
    }
}