package crypto;

import org.junit.jupiter.api.*;
import java.io.IOException;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class KeyManagerTest {

    private static final String PRIVATE_KEY_PATH = "test-keys/test_private.key";
    private static final String PUBLIC_KEY_PATH = "test-keys/test_public.key";

    @BeforeAll
    static void setup() throws IOException {
        Files.createDirectories(Paths.get("test-keys"));
    }

    @AfterAll
    static void cleanup() throws IOException {
        Files.deleteIfExists(Paths.get(PRIVATE_KEY_PATH));
        Files.deleteIfExists(Paths.get(PUBLIC_KEY_PATH));
        Files.deleteIfExists(Paths.get("test-keys"));
    }

    @Test
    @Order(1)
    void testGenerateAndStoreKeyPair() throws Exception {
        // Act
        KeyManager.generateAndStoreKeyPair(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH);

        // Assert
        assertTrue(Files.exists(Paths.get(PRIVATE_KEY_PATH)), "Private key file should exist");
        assertTrue(Files.exists(Paths.get(PUBLIC_KEY_PATH)), "Public key file should exist");

        String privContent = Files.readString(Paths.get(PRIVATE_KEY_PATH));
        String pubContent = Files.readString(Paths.get(PUBLIC_KEY_PATH));

        assertTrue(privContent.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(pubContent.contains("-----BEGIN PUBLIC KEY-----"));
    }

    @Test
    @Order(2)
    void testKeyPairExists() {
        assertTrue(KeyManager.keyPairExists(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH),
                "keyPairExists should return true after keys are created");
    }

    @Test
    @Order(3)
    void testLoadPrivateKeyAndPublicKey() throws Exception {
        PrivateKey privateKey = KeyManager.loadPrivateKey(PRIVATE_KEY_PATH);
        PublicKey publicKey = KeyManager.loadPublicKey(PUBLIC_KEY_PATH);

        assertNotNull(privateKey, "Loaded private key should not be null");
        assertNotNull(publicKey, "Loaded public key should not be null");
        assertEquals("RSA", privateKey.getAlgorithm(), "Private key algorithm should be RSA");
        assertEquals("RSA", publicKey.getAlgorithm(), "Public key algorithm should be RSA");
    }
}
