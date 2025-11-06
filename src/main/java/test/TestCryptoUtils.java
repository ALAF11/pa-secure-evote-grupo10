package test;

import crypto.CryptoUtils;

import java.security.KeyPair;

public class TestCryptoUtils {
    public static void main(String[] args) throws Exception {
        KeyPair keyPair = CryptoUtils.generateKeyPair(); //gera par de chaves assimétrico

        String message = "Voto secreto";
        byte[] signature = CryptoUtils.sign(message.getBytes(), keyPair.getPrivate()); //assina digitalmente o conteúdo da chave privada

        boolean valid = CryptoUtils.verifySignature(message.getBytes(), signature, keyPair.getPublic()); //chave pública para verificar a assinatura
        System.out.println("Assinatura válida? " + valid);
    }
}
