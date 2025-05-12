package model;

import exception.EVotingException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Represents a share of a secret key in a threshold cryptography scheme.
 * <p>
 * This class implements Shamir's Secret Sharing , allowing a key to be split
 * into multiple parts, with a threshold number required for reconstruction.
 * <p>
 * Each share contains:
 * <ul>
 *     <li>An x-coordinate (the share identifier)</li>
 *     <li>A y-coordinate (the share value)</li>
 *     <li>The prime modulus used in the finite field</li>
 *     <li>A verification hash to ensure the share hasn't been tampered with</li>
 * </ul>
 * <p>
 * This is used by the Tallying Authority to split its private key among
 * multiple trustees, requiring collaboration for vote decryption.
 */

public class KeyShare {
    private final int x;
    private final BigInteger y;
    private final BigInteger prime;
    private final byte[] verificationHash;

    /**
     * Constructs a key share with the specified coordinates and prime modulus.
     *
     * @param x The x-coordinate of the share (share identifier)
     * @param y The y-coordinate of the share (share value)
     * @param prime The prime modulus for the finite field
     */

    public KeyShare(int x, BigInteger y, BigInteger prime) {
        this.x = x;
        this.y = y;
        this.prime = prime;
        this.verificationHash = generateVerificationHash();
    }

    /**
     * Constructs a key share with the specified coordinates and a default
     * large prime.
     * <p>
     * Uses a 2048-bit prime by default.
     *
     * @param x The x-coordinate of the share (share identifier)
     * @param y The y-coordinate of the share (share value)
     */

    public KeyShare(int x, BigInteger y) {
        this(x, y, BigInteger.valueOf(2).pow(2048).subtract(BigInteger.ONE));
    }

    /**
     * Gets the x-coordinate (identifier) of the share.
     *
     * @return The x-coordinate
     */

    public int getX() {
        return x;
    }

    /**
     * Gets the y-coordinate (value) of the share.
     *
     * @return The y-coordinate
     */

    public BigInteger getY() {
        return y;
    }

    /**
     * Verifies that the share has not been tampered with.
     * <p>
     * This method recomputes the hash of the share's components and
     * compares it to the stored verification hash.
     *
     * @return true if the share is valid, false if it has been modified
     */

    public boolean verify() {
        byte[] currentHash = generateVerificationHash();
        return MessageDigest.isEqual(verificationHash, currentHash);
    }

    /**
     * Generates a cryptographic hash of the share's components.
     * <p>
     * This hash is used to verify the integrity of the share later.
     *
     * @return A SHA-256 hash of the share's components
     */

    private byte[] generateVerificationHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(BigInteger.valueOf(x).toByteArray());
            digest.update(y.toByteArray());
            digest.update(prime.toByteArray());
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new EVotingException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Checks equality of key shares.
     *
     * @param o The object to compare
     * @return true if equal, false otherwise
     */

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyShare keyShare = (KeyShare) o;
        return x == keyShare.x &&
                y.equals(keyShare.y) &&
                prime.equals(keyShare.prime);
    }

    /**
     * Generates hash code.
     *
     * @return hash code
     */

    @Override
    public int hashCode() {
        return Objects.hash(x, y, prime);
    }

    /**
     * Generates string representation.
     *
     * @return string representation
     */

    @Override
    public String toString() {
        return "KeyShare{" +
                "x=" + x +
                ", y=" + y +
                ", prime=" + prime +
                '}';
    }
}
