package exception;

/**
 * Base exception class for all exceptions in the e-voting system.
 * <p>
 * This class serves as the parent for all custom exceptions in the pa-secure-evote
 * system. It extends RuntimeException to allow for unchecked exceptions throughout
 * the application, reducing the need for explicit exception handling in every method.
 * <p>
 * Leveraging a custom exception hierarchy allows the system to provide more specific
 * error information and to implement targeted exception handling across different components.
 */

public class EVotingException extends RuntimeException {

    /**
     * Constructs a new e-voting exception with the specified detail message.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     */

    public EVotingException(String message) {
        super(message);
    }

    /**
     * Constructs a new e-voting exception with the specified detail message and cause.
     *
     * @param message The detail message (which is saved for later retrieval by the getMessage() method)
     * @param cause The cause (which is saved for later retrieval by the getCause() method)
     */

    public EVotingException(String message, Throwable cause) {
        super(message, cause);
    }
}
