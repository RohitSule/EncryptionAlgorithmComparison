package app;

import java.util.concurrent.TimeUnit;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import java.security.*;

class Ecdsa extends Thread {
    int counter = 0;
    static long time_second = 0;

    public static void main(String[] args) throws Exception {
        String user_input = "Yash_dave@gmail.com";
        byte[] value = user_input.getBytes();
        System.out.println("Input Array:" + value);
        KeyPair key = generateKeyPair();
        PrivateKey private_key = key.getPrivate();
        System.out.println("Private key :" + private_key);
        byte[] sign = generateSignature(private_key, value);
        System.out.println("Signature :" + sign);
        PublicKey public_key = key.getPublic();
        System.out.println("Public key :" + public_key);
        Boolean check = verifySignature(public_key, value, sign);
        if (check == true) {
            System.out.println("Verified");
        } else {
            System.out.println("Not verified");
        }
    }

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleFipsProvider());
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("EC", "BCFIPS");
        keyPair.initialize(384);
        return keyPair.generateKeyPair();
    }

    public static byte[] generateSignature(PrivateKey ecPrivate, byte[] input) throws GeneralSecurityException {
        Thread u = new Ecdsa();
        u.start();
        Signature signature = Signature.getInstance("SHA384withECDSA", "BCFIPS");
        signature.initSign(ecPrivate);
        signature.update(input);
        return signature.sign();
    }

    public static boolean verifySignature(PublicKey ecPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA384withECDSA", "BCFIPS");
        signature.initVerify(ecPublic);
        signature.update(input);
        System.out.println("Execution time in seconds :" + TimeUnit.MILLISECONDS.toHours(time_second));
        return signature.verify(encSignature);
    }

    public void run() {
        while (true) {

            time_second = counter++;

        }
    }
}