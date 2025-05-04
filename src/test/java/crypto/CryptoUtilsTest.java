package crypto;

import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.*;

public class CryptoUtilsTest {

    @Test
    public void testSignatureAndVerification() throws Exception {
        KeyPair keyPair = CryptoUtils.generateKeyPair();

        String message = "Voto secreto";
        byte[] signature = CryptoUtils.sign(message.getBytes(), keyPair.getPrivate());

        boolean isValid = CryptoUtils.verifySignature(message.getBytes(), signature, keyPair.getPublic());

        assertTrue(isValid, "A assinatura deve ser válida para a mensagem original");
    }

    @Test
    public void testTamperedMessageFailsVerification() throws Exception {
        KeyPair keyPair = CryptoUtils.generateKeyPair();

        String message = "Candidato A";
        byte[] signature = CryptoUtils.sign(message.getBytes(), keyPair.getPrivate());

        // Mensagem adulterada
        String tampered = "Candidato B";

        boolean isValid = CryptoUtils.verifySignature(tampered.getBytes(), signature, keyPair.getPublic());

        assertFalse(isValid, "A verificação deve falhar se a mensagem for alterada");
    }

    @Test
    public void testEncryptionDecryption() throws Exception {
        KeyPair keyPair = CryptoUtils.generateKeyPair();

        String message = "Mensagem ultra secreta";
        byte[] encrypted = CryptoUtils.encrypt(message.getBytes(), keyPair.getPublic());
        byte[] decrypted = CryptoUtils.decrypt(encrypted, keyPair.getPrivate());

        assertEquals(message, new String(decrypted), "A mensagem desencriptada deve ser igual à original");
    }

    @Test
    public void testKeyToBase64AndBack() throws Exception {
        KeyPair keyPair = CryptoUtils.generateKeyPair();

        String pubEncoded = CryptoUtils.keyToBase64(keyPair.getPublic());
        String privEncoded = CryptoUtils.keyToBase64(keyPair.getPrivate());

        assertNotNull(CryptoUtils.base64ToPublicKey(pubEncoded));
        assertNotNull(CryptoUtils.base64ToPrivateKey(privEncoded));
    }
}
