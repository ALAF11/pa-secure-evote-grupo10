package exception;

/**
 * Exception thrown when authentication-related issues occur in the e-voting system.
 * <p>
 * This exception is thrown in scenarios such as:
 * <ul>
 *     <li>Invalid voter certificates</li>
 *     <li>Expired certificates</li>
 *     <li>Revoked certificates</li>
 *     <li>Invalid voting tokens</li>
 *     <li>Unauthorized access attempts</li>
 * </ul>
 * <p>
 * This exception may be thrown by components such as {@code VotingServer} or {@code BallotBox}
 * during the validation of voter credentials or tokens.
 */

public class AuthenticationException extends EVotingException {

    /**
     * Constructs a new authentication exception with the specified detail message.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     */

    public AuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructs a new authentication exception with the specified detail message and cause.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     * @param cause The cause (which is saved for later retrieval by the getCause() method)
     */

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
