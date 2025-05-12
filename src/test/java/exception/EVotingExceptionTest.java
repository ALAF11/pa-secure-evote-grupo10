package exception;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class EVotingExceptionTest {

    @Test
    @DisplayName("Should create exception with message")
    void constructor_WithMessage_ShouldCreateException() {

        String errorMessage = "Test error message";

        EVotingException exception = new EVotingException(errorMessage);

        assertEquals(errorMessage, exception.getMessage(), "Message should match the provided error message");
        assertTrue(exception instanceof RuntimeException, "Should be a RuntimeException");
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void constructor_WithMessageAndCause_ShouldCreateException() {

        String errorMessage = "Test error message";
        Throwable cause = new IllegalArgumentException("Test cause");

        EVotingException exception = new EVotingException(errorMessage, cause);

        assertEquals(errorMessage, exception.getMessage(), "Message should match the provided error message");
        assertEquals(cause, exception.getCause(), "Cause should match the provided cause");
    }
}
