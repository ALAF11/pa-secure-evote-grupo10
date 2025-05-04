package model;

import java.util.UUID;

//Token model issued by Voting Server after voter authentication

public class Token {

    private final UUID tokenId;
    private final long issuedAt;

    public Token() {
        this.tokenId = UUID.randomUUID();
        this.issuedAt = System.currentTimeMillis();
    }

    public UUID getTokenId() {
        return tokenId;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    @Override
    public String toString() {
        return "Token[" + tokenId + "at" + issuedAt + "]";
    }
}
