package exception;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class VoteSubmissionExceptionTest {

    @Test
    @DisplayName("Should create vote submission exception with message")
    void constructor_WithMessage_ShouldCreateException() {

        String errorMessage = "Vote submission failed";

        VoteSubmissionException exception = new VoteSubmissionException(errorMessage);

        assertEquals(errorMessage, exception.getMessage(), "Message should match the provided error message");
        assertTrue(exception instanceof EVotingException, "Should be an EVotingException");
    }

    @Test
    @DisplayName("Should create vote submission exception with message and cause")
    void constructor_WithMessageAndCause_ShouldCreateException() {

        String errorMessage = "Vote submission failed";
        Throwable cause = new IllegalStateException("Connection lost");

        VoteSubmissionException exception = new VoteSubmissionException(errorMessage, cause);

        assertEquals(errorMessage, exception.getMessage(), "Message should match the provided error message");
        assertEquals(cause, exception.getCause(), "Cause should match the provided cause");
    }

    @Test
    @DisplayName("Should inherit from EVotingException")
    void inheritance_ShouldBeEVotingException() {

        VoteSubmissionException exception = new VoteSubmissionException("Test");

        assertTrue(exception instanceof EVotingException, "Should be an EVotingException");
    }
}
