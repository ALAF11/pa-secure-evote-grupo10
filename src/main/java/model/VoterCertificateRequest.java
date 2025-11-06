package model;

import crypto.CryptoUtils;

import java.security.PublicKey;
import java.util.UUID;

public class VoterCertificateRequest {

    private final String id;
    private String name;
    private final PublicKey publicKey;

    public VoterCertificateRequest(String name, PublicKey publicKey) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
        this.publicKey = publicKey;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] toBytes() {
        return (id + name + CryptoUtils.keyToBase64(publicKey)).getBytes();
    }

    public Certificate toCertificate(byte[] signature) {
        return new Certificate();
    }

}
