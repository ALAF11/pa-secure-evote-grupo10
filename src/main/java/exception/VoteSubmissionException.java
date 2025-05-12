package exception;

/**
 * Exception thrown when issues occur during vote submission to the ballot box.
 * <p>
 * This exception is thrown in scenarios such as:
 * <ul>
 *     <li>Invalid vote format or encryption</li>
 *     <li>Duplicate voting attempts</li>
 *     <li>Ballot box storage failures</li>
 *     <li>Voting period has ended</li>
 *     <li>Network or connectivity issues during vote submission</li>
 * </ul>
 * <p>
 * The BallotBox component typically throws this exception when validation
 * or storage of submitted votes fails.
 */

public class VoteSubmissionException extends EVotingException{

    /**
     * Constructs a new vote submission exception with the specified detail message.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     */

    public VoteSubmissionException(String message) {
        super(message);
    }

    /**
     * Constructs a new vote submission exception with the specified detail message and cause.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     * @param cause The cause (which is saved for later retrieval by the getCause() method)
     */

    public VoteSubmissionException(String message, Throwable cause) {
        super(message, cause);
    }
}
