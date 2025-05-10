package exception;

public class EVotingException extends RuntimeException {

    public EVotingException(String message) {
        super(message);
    }

    public EVotingException(String message, Throwable cause) {
        super(message, cause);
    }
}
