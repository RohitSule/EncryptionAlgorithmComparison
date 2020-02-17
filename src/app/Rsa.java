package app;

import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import java.security.*;

class Rsa extends Thread {
    int counter = 0;
    static long time_second = 0;

    public static void main(String[] args) throws Exception {
        String user_input = "Hello";
        byte[] value = user_input.getBytes();
        System.out.println("Encrypted Key :"+value);
        KeyPair key = generateKeyPair();
        PrivateKey private_key = key.getPrivate();
        System.out.println("Private key :" + private_key);
        byte[] sign = generatePkcs1Signature(private_key, value);
        System.out.println("Signature :"+sign);
        PublicKey public_key = key.getPublic();
        Boolean check = verifyPkcs1Signature(public_key, value, sign);
        if(check==true){
            System.out.println("Verified");
        }
        else{
            System.out.println("Not verified");
        }
    }

    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        Security.addProvider(new BouncyCastleFipsProvider());
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BCFIPS");
        keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return keyPair.generateKeyPair();
    }

    public static byte[] generatePkcs1Signature(PrivateKey rsaPrivate, byte[] input) throws GeneralSecurityException {
        Thread u = new Rsa();
        u.start();
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");
        signature.initSign(rsaPrivate);
        signature.update(input);
        return signature.sign();
    }

    public static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");
        signature.initVerify(rsaPublic);
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