import static org.junit.jupiter.api.Assertions.*;

import model.KeyShare;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;

public class KeyShareTest {

    @Test
    @DisplayName("Tests constructor with three parameters and getters")
    public void testConstructorAndGetters() {
        int x = 1;
        BigInteger y = new BigInteger("123456789");
        BigInteger prime = BigInteger.valueOf(23);
        KeyShare keyShare = new KeyShare(x, y, prime);

        assertEquals(x, keyShare.getX());
        assertEquals(y, keyShare.getY());
    }

    @Test
    @DisplayName("Tests secondary constructor with default prime value")
    public void testSecondaryConstructor() {
        int x = 2;
        BigInteger y = new BigInteger("987654321");
        KeyShare keyShare = new KeyShare(x, y);

        assertEquals(x, keyShare.getX());
        assertEquals(y, keyShare.getY());
    }

    @Test
    @DisplayName("Tests equals and hashCode methods")
    public void testEqualsAndHashCode() {
        int x = 1;
        BigInteger y = new BigInteger("123456789");
        BigInteger prime = BigInteger.valueOf(23);
        KeyShare keyShare1 = new KeyShare(x, y, prime);
        KeyShare keyShare2 = new KeyShare(x, y, prime);
        KeyShare differentKeyShare = new KeyShare(2, y, prime);

        // Test equality
        assertEquals(keyShare1, keyShare2);
        assertNotEquals(keyShare1, differentKeyShare);

        // Test hashCode
        assertEquals(keyShare1.hashCode(), keyShare2.hashCode());
        assertNotEquals(keyShare1.hashCode(), differentKeyShare.hashCode());
    }

    @Test
    @DisplayName("Tests toString method returns expected format")
    public void testToString() {
        int x = 1;
        BigInteger y = new BigInteger("123456789");
        BigInteger prime = BigInteger.valueOf(23);
        KeyShare keyShare = new KeyShare(x, y, prime);

        String expected = "KeyShare{" +
                "x=" + x +
                ", y=" + y +
                ", prime=" + prime +
                '}';
        assertEquals(expected, keyShare.toString());
    }
}