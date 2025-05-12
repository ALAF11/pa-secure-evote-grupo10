package exception;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AuthenticationExceptionTest {

    @Test
    @DisplayName("Should create authentication exception with message")
    void constructor_WithMessage_ShouldCreateException() {

        String errorMessage = "Invalid credentials";

        AuthenticationException exception = new AuthenticationException(errorMessage);

        assertEquals(errorMessage, exception.getMessage(), "Message should match the provided error message");
        assertTrue(exception instanceof EVotingException, "Should be an EVotingException");
    }

    @Test
    @DisplayName("Should inherit from EVotingException")
    void inheritance_ShouldBeEVotingException() {

        AuthenticationException exception = new AuthenticationException("Test");

        assertTrue(exception instanceof EVotingException, "Should be an EVotingException");
    }
}
