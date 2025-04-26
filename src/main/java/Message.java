import java.io.Serializable;

public class Message implements Serializable {

    private final byte[] message;

    public Message ( byte[] message ) {
        this.message = message;
    }

    public byte[] getMessage ( ) {
        return message;
    }
}