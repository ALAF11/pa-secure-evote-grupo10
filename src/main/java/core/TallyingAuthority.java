package core;

import exception.EVotingException;
import model.KeyShare;
import org.slf4j.Logger;
import util.LoggingUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Represents the Tallying Authority in the e-voting system.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Decrypting and tallying votes after the election concludes</li>
 *     <li>Implementing key sharing for threshold cryptography</li>
 *     <li>Publishing election results</li>
 * </ul>
 * <p>
 * The Tallying Authority uses a secret sharing scheme (Shamir's Secret Sharing)
 * to split its private key into multiple shares, requiring a threshold number
 * of shares to reconstruct the key for vote decryption.
 */

public class TallyingAuthority {
    private static final Logger logger = LoggingUtil.getLogger(TallyingAuthority.class);
    private final KeyPair keyPair;
    private final Map<String, Integer> results = new HashMap<>();
    private final BigInteger prime;
    private List<KeyShare> keyShares;
    private BigInteger privateKeyBigInt;
    private final BigInteger modulus; // Store the modulus for reconstruction

    /**
     * Constructs a new Tallying Authority with RSA key pair.
     *
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available
     */

    public TallyingAuthority() throws NoSuchAlgorithmException {
        logger.info("Initializing Tallying Authority");

        // Generate the Tallying Authority's key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        this.keyPair = keyGen.generateKeyPair();

        // Initialize prime for secret sharing
        this.prime = BigInteger.valueOf(2).pow(2048).subtract(BigInteger.ONE);

        // Extract modulus and private exponent from the RSA key pair
        RSAPrivateCrtKey rsaKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        this.modulus = rsaKey.getModulus();
        this.privateKeyBigInt = rsaKey.getPrivateExponent();

        logger.info("Tallying Authority initialized successfully");
    }

    /**
     * Splits the private key into multiple shares using Shamir's Secret Sharing.
     * <p>
     * This implements a threshold cryptography scheme were at least 'k' out of 'n'
     * shares are required to reconstruct the private key.
     *
     * @param n The total number of shares to create
     * @param k The threshold number of shares required for reconstruction
     * @throws IllegalArgumentException If n is less than k
     */

    public void splitKey(int n, int k) {
        if (n < k) {
            throw new IllegalArgumentException("Total shares (n) must be greater than or equal to threshold (k)");
        }

        logger.info("Splitting private key into {} shares with threshold {}", n, k);

        SecureRandom random = new SecureRandom();
        keyShares = new ArrayList<>();

        // Generate random coefficients for the polynomial
        BigInteger[] coefficients = new BigInteger[k];
        coefficients[0] = privateKeyBigInt; // The secret is the constant term

        for (int i = 1; i < k; i++) {
            coefficients[i] = new BigInteger(prime.bitLength() - 1, random);
        }

        // Generate shares
        for (int i = 1; i <= n; i++) {
            // Evaluate polynomial at point i
            BigInteger x = BigInteger.valueOf(i);
            BigInteger y = coefficients[0];

            for (int j = 1; j < k; j++) {
                BigInteger term = coefficients[j].multiply(x.pow(j)).mod(prime);
                y = y.add(term).mod(prime);
            }

            keyShares.add(new KeyShare(i, y, prime));
        }

        logger.info("Key splitting completed successfully");
    }

    /**
     * Reconstructs the private key from provided shares.
     *
     * @param shares The key shares for reconstruction
     * @return The reconstructed private exponent
     */

    private BigInteger reconstructKey(List<KeyShare> shares) {
        if (shares.size() < 2) {
            throw new IllegalArgumentException("At least 2 shares are required for reconstruction");
        }

        logger.info("Reconstructing private key from {} shares", shares.size());

        BigInteger reconstructed = BigInteger.ZERO;


        for (int i = 0; i < shares.size(); i++) {
            KeyShare share = shares.get(i);
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for (int j = 0; j < shares.size(); j++) {
                if (i != j) {
                    KeyShare other = shares.get(j);
                    BigInteger iValue = BigInteger.valueOf(share.getX());
                    BigInteger jValue = BigInteger.valueOf(other.getX());

                    numerator = numerator.multiply(jValue.negate()).mod(prime);
                    denominator = denominator.multiply(iValue.subtract(jValue)).mod(prime);
                }
            }

            BigInteger inverseDenominator = denominator.modInverse(prime);
            BigInteger delta = numerator.multiply(inverseDenominator).mod(prime);
            BigInteger term = share.getY().multiply(delta).mod(prime);

            reconstructed = reconstructed.add(term).mod(prime);
        }

        logger.info("Key reconstruction completed successfully");
        return reconstructed;
    }

    /**
     * Converts a BigInteger to PrivateKey.
     *
     * @param privateExponent The private exponent to convert
     * @return The PrivateKey instance
     * @throws EVotingException If conversion fails
     */

    private PrivateKey convertToPrivateKey(BigInteger privateExponent) {
        try {
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new EVotingException("Failed to convert private exponent to key", e);
        }
    }

    /**
     * Decrypts and tallies the votes using the reconstructed private key.
     * <p>
     * This method requires a threshold number of key shares to reconstruct
     * the private key before decryption can occur.
     *
     * @param encryptedVotes The list of encrypted votes to tally
     * @param shares The list of key shares for private key reconstruction
     */

    public void decryptAndTallyVotes(List<byte[]> encryptedVotes, List<KeyShare> shares) {
        String transactionId = "TALLY_" + UUID.randomUUID();
        LoggingUtil.setTransactionContext(transactionId);

        try {
            logger.info("Starting vote tallying process");

            // Clear previous results
            results.clear();

            // Reconstruct the private key from shares
            BigInteger reconstructedKey = reconstructKey(shares);

            // Convert reconstructed key to PrivateKey object
            PrivateKey privateKey = convertToPrivateKey(reconstructedKey);
            logger.info("Successfully converted reconstructed key to PrivateKey");

            logger.info("Decrypting {} votes", encryptedVotes.size());

            // Decrypt and tally each vote using the reconstructed key
            for (byte[] encryptedVote : encryptedVotes) {
                try {
                    String decryptedVote = decryptVote(encryptedVote, privateKey);

                    // Update tally
                    results.put(decryptedVote, results.getOrDefault(decryptedVote, 0) + 1);
                } catch (Exception e) {
                    logger.warn("Failed to decrypt vote: {}", e.getMessage());
                }
            }

            logger.info("Vote tallying completed successfully");
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

    /**
     * Decrypts a single encrypted vote using the private key.
     *
     * @param encryptedVote The encrypted vote
     * @param privateKey The private key for decryption
     * @return The decrypted vote
     * @throws EVotingException If decryption fails
     */

    private String decryptVote(byte[] encryptedVote, PrivateKey privateKey) {
        try {
            // Parse encrypted vote components
            ByteBuffer buffer = ByteBuffer.wrap(encryptedVote);

            // Extract encrypted key
            int keyLength = buffer.getInt();
            byte[] encryptedKey = new byte[keyLength];
            buffer.get(encryptedKey);

            // Extract IV
            int ivLength = buffer.getInt();
            byte[] iv = new byte[ivLength];
            buffer.get(iv);

            // Extract encrypted vote
            int voteLength = buffer.getInt();
            byte[] encryptedVoteData = new byte[voteLength];
            buffer.get(encryptedVoteData);

            // Decrypt AES key using the reconstructed RSA private key
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);

            // Decrypt vote using AES key
            SecretKeySpec aesKey = new SecretKeySpec(decryptedKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParams = new GCMParameterSpec(128, iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmParams);
            byte[] decryptedVoteBytes = aesCipher.doFinal(encryptedVoteData);

            return new String(decryptedVoteBytes);
        } catch (Exception e) {
            throw new EVotingException("Vote decryption failed", e);
        }
    }

    /**
     * Publishes the election results.
     * <p>
     * Generates a formatted report of the election results including
     * the number of votes for each candidate.
     */

    public void publishResults() {
        logger.info("Publishing election results");
        StringBuilder report = new StringBuilder();

        report.append("==== ELECTION RESULTS ====\n");
        report.append("Report generated at: ").append(Instant.now()).append("\n");
        report.append("Total votes: ").append(results.values().stream().mapToInt(Integer::intValue).sum()).append("\n\n");

        results.forEach((candidate, count) ->
                report.append(candidate).append(": ").append(count).append(" votes\n"));

        report.append("==========================");

        logger.debug("{}", report);
        logger.info("Results published successfully");
    }

    /**
     * Gets the public key for the Tallying Authority.
     *
     * @return The public key
     */

    public java.security.PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    /**
     * Gets all key shares.
     *
     * @return List of key shares
     */

    public List<KeyShare> getKeyShares() {
        return new ArrayList<>(keyShares);
    }

    /**
     * Gets the election results.
     *
     * @return A map containing candidates and their vote counts
     */

    public Map<String, Integer> getResults() {
        return new HashMap<>(results);
    }
}
