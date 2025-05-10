package exception;

public class VoteSubmissionException extends EVotingException{

    public VoteSubmissionException(String message) {
        super(message);
    }

    public VoteSubmissionException(String message, Throwable cause) {
        super(message, cause);
    }
}
