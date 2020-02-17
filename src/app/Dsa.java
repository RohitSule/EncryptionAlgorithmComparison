package app;

import java.util.concurrent.TimeUnit;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import java.security.*;

class Dsa extends Thread {
    int counter = 0;
    static long time_second = 0;

    public static void main(String[] args) throws Exception {
        String user_input = "Hello";
        byte[] value = user_input.getBytes();
        System.out.println("Encrypted Key :" + value);
        KeyPair key = generateKeyPair();
        PrivateKey private_key = key.getPrivate();
        System.out.println("Private key :" + private_key);
        byte[] sign = generateSignature(private_key, value);
        System.out.println("Signature :" + sign);
        PublicKey public_key = key.getPublic();
        System.out.println("Public key :"+public_key);
        Boolean check = verifySignature(public_key, value, sign);
        if (check == true) {
            System.out.println("Verified");
        } else {
            System.out.println("Not verified");
        }
    }

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleFipsProvider());
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DSA", "BCFIPS");
        keyPair.initialize(3072);
        return keyPair.generateKeyPair();
    }

    public static byte[] generateSignature(PrivateKey dsaPrivate, byte[] input) throws GeneralSecurityException {
        Thread u = new Dsa();
        u.start();
        Signature signature = Signature.getInstance("SHA384withDSA", "BCFIPS");
        signature.initSign(dsaPrivate);
        signature.update(input);
        return signature.sign();
    }

    public static boolean verifySignature(PublicKey dsaPublic, byte[] input, byte[] encSignature) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA384withDSA", "BCFIPS");
        signature.initVerify(dsaPublic);
        signature.update(input);
        System.out.println("Execution time in seconds :"+TimeUnit.MILLISECONDS.toHours(time_second));
        return signature.verify(encSignature);
    }

    public void run() {
        while (true) {

            time_second = counter++;

        }
    }
}