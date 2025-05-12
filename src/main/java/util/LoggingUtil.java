package util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

/**
 * Provides centralized logging utilities for the e-voting system.
 * <p>
 * This utility class is responsible for:
 * <ul>
 *     <li>Creating and configuring loggers for different components</li>
 *     <li>Managing transaction contexts through MDC (Mapped Diagnostic Context)</li>
 *     <li>Managing user contexts for audit logging</li>
 * </ul>
 * <p>
 * The class uses SLF4J for logging to provide a consistent interface
 * regardless of the underlying logging implementation.
 */

public class LoggingUtil {

    /**
     * Private constructor to prevent instantiation of utility class.
     */

    private LoggingUtil(){
        // Prevent instantiation
    }

    /**
     * Gets a logger for the specified class.
     *
     * @param clazz The class to get the logger for
     * @return A configured SLF4J Logger instance
     */

    public static Logger getLogger(Class<?> clazz) {
        return LoggerFactory.getLogger(clazz);
    }

    /**
     * Sets the transaction context in the MDC.
     * <p>
     * This method is used to track operations across multiple components
     * that are part of the same logical transaction.
     *
     * @param transactionId The ID of the transaction to set in the context
     */

    public static void setTransactionContext(String transactionId) {
        MDC.put("transactionId", transactionId);
    }

    /**
     * Clears the transaction context from the MDC.
     * <p>
     * Should be called when a transaction is completed to prevent
     * context leakage between different transactions.
     */

    public static void clearTransactionContext() {
        MDC.remove("transactionId");
    }

    /**
     * Sets the user context in the MDC.
     * <p>
     * This method is used to associate log entries with a specific user,
     * which is particularly useful for security audit logging.
     *
     * @param userId The ID of the user to set in the context
     */

    public static void setUserContext(String userId) {
        MDC.put("userId", userId);
    }

    /**
     * Clears the user context from the MDC.
     * <p>
     * Should be called when operations for a specific user are completed
     * to prevent context leakage between different user operations.
     */

    public static void clearUserContext() {
        MDC.remove("userId");
    }

}
