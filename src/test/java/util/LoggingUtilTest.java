package util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.MDC;

import static org.junit.jupiter.api.Assertions.*;

class LoggingUtilTest {

    @AfterEach
    public void tearDown() {
        // Clear MDC entries after each test to prevent test interference
        MDC.clear();
    }

    @Test
    @DisplayName("Verifies that LoggingUtil.getLogger() correctly returns a Logger instance with the proper class name as identifier")
    public void testGetLogger(){
        Logger logger = LoggingUtil.getLogger(LoggingUtilTest.class);
        assertNotNull(logger);
        assertEquals("util.LoggingUtilTest", logger.getName());
    }

    @Test
    @DisplayName("Validates that setting a transaction context properly stores it in MDC and clearing it removes the value")
    public void testSetAndClearTransactionContext() {
        // Test setting transaction context
        String transactionId = "test-transaction-123";
        LoggingUtil.setTransactionContext(transactionId);
        assertEquals(transactionId, MDC.get("transactionId"));

        // Test clearing transaction context
        LoggingUtil.clearTransactionContext();
        assertNull(MDC.get("transactionId"));
    }

    @Test
    @DisplayName("Ensures that user context is correctly added to MDC when set and properly removed when cleared")
    public void testSetAndClearUserContext() {
        // Test setting user context
        String userId = "test-user-123";
        LoggingUtil.setUserContext(userId);
        assertEquals(userId, MDC.get("userId"));

        //Test clearing user context
        LoggingUtil.clearUserContext();
        assertNull(MDC.get("userId"));
    }

    @Test
    @DisplayName("Confirms that multiple context values can exist simultaneously in MDC and can be cleared independently")
    public void testMultipleContextValues() {
        //Test setting both transaction and user context simultaneously
        String transactionId = "transactionId-456";
        String userId = "user-456";

        LoggingUtil.setTransactionContext(transactionId);
        LoggingUtil.setUserContext(userId);

        assertEquals(transactionId, MDC.get("transactionId"));
        assertEquals(userId, MDC.get("userId"));

        // Clear only transaction context and verify user context remains
        LoggingUtil.clearTransactionContext();
        assertNull(MDC.get("transactionId"));
        assertEquals(userId, MDC.get("userId"));

        // Clear user context and verify both are null
        LoggingUtil.clearUserContext();
        assertNull(MDC.get("transactionId"));
        assertNull(MDC.get("userId"));
    }

    @Test
    @DisplayName("Verifies that clearing context values that haven't been set doesn't cause errors")
    public void testClearingNonExistentContent() {
        // Test clearing context that weren't set
        LoggingUtil.clearTransactionContext();
        LoggingUtil.clearUserContext();
        assertNull(MDC.get("transactionId"));
        assertNull(MDC.get("userId"));
    }

}