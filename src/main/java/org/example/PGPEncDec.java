package org.example;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;

public class PGPEncDec {

    public static void main(String[] args) throws Exception {
        String originalMessage = "Hello, this is a PGP encryption example!";
        String passphrase = "my_passphrase";


        // Generate PGP key pair
        KeyPair keyPair = generateKeyPair();

        // Encrypt the message
        byte[] encryptedMessage = encrypt(originalMessage, (PGPPublicKey) keyPair.getPublic(), passphrase);

        System.out.println("Encrypted message: " + new String(encryptedMessage));

        // Decrypt the message
        String decryptedMessage = decrypt(encryptedMessage, (PGPSecretKey) keyPair.getPrivate(), passphrase);
        System.out.println("Decrypted message: " + decryptedMessage);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    private static byte[] encrypt(byte[] message, PublicKey publicKey, String passphrase) throws Exception {
        // keys may be in file
        KeyPair keyPair = generateKeyPair();

        // private may be provided in file
        PrivateKey privateKey = keyPair.getPrivate();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(message);
    }

    private static String decrypt(byte[] encryptedMessage, PGPSecretKey privateKey, String passphrase) throws Exception {
        InputStream inputStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedMessage));

        PGPObjectFactory objectFactory = new PGPObjectFactory(inputStream);
        PGPEncryptedDataList encryptedDataList;

        Object object = objectFactory.nextObject();
        if (object instanceof PGPEncryptedDataList) {
            encryptedDataList = (PGPEncryptedDataList) object;
        } else {
            encryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        }

        PGPPBEEncryptedData pbeEncryptedData = (PGPPBEEncryptedData) encryptedDataList.get(0);
        InputStream decryptedInputStream = pbeEncryptedData.getDataStream(new JcePBEDataDecryptorFactoryBuilder(new BcPGPDigestCalculatorProvider()).setProvider("BC").build(passphrase.toCharArray()));
        objectFactory = new PGPObjectFactory(decryptedInputStream);
        object = objectFactory.nextObject();

        if (object instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData) object;
            objectFactory = new PGPObjectFactory(compressedData.getDataStream());
            object = objectFactory.nextObject();
        }

        PGPLiteralData literalData = (PGPLiteralData) object;
        InputStream literalDataInputStream = literalData.getInputStream();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        int ch;
        while ((ch = literalDataInputStream.read()) >= 0) {
            output.write(ch);
        }

        byte[] decryptedBytes = output.toByteArray();
        return new String(decryptedBytes, "UTF-8");
    }
}
