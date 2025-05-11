package model;

import exception.EVotingException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;


public class KeyShare {
    private final int x;
    private final BigInteger y;
    private final BigInteger prime;
    private final byte[] verificationHash;


    public KeyShare(int x, BigInteger y, BigInteger prime) {
        this.x = x;
        this.y = y;
        this.prime = prime;
        this.verificationHash = generateVerificationHash();
    }


    public KeyShare(int x, BigInteger y) {
        this(x, y, BigInteger.valueOf(2).pow(2048).subtract(BigInteger.ONE));
    }


    public int getX() {
        return x;
    }


    public BigInteger getY() {
        return y;
    }

    public boolean verify() {
        byte[] currentHash = generateVerificationHash();
        return MessageDigest.isEqual(verificationHash, currentHash);
    }

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyShare keyShare = (KeyShare) o;
        return x == keyShare.x &&
                y.equals(keyShare.y) &&
                prime.equals(keyShare.prime);
    }

    @Override
    public int hashCode() {
        return Objects.hash(x, y, prime);
    }

    @Override
    public String toString() {
        return "KeyShare{" +
                "x=" + x +
                ", y=" + y +
                ", prime=" + prime +
                '}';
    }
}
