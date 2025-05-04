package model;

import java.io.Serializable;
import java.util.Arrays;

//Simple encrypted voting model

public class Vote implements Serializable {

    private final byte[] encryptedVote;
    private final Token token;

    public Vote(byte[] encryptedVote, Token token){
        this. encryptedVote = encryptedVote;
        this.token = token;
    }

    public byte[] getEncryptedVote() {
        return encryptedVote;
    }

    public Token getToken() {
        return token;
    }

    @Override
    public String toString() {
        return "EncryptedVote[" + Arrays.toString(encryptedVote) + "]";
    }


}
