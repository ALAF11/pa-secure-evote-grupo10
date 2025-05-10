package util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

public class LoggingUtil {

    private LoggingUtil(){
        // Prevent instantiation
    }

    public static Logger getLogger(Class<?> clazz) {
        return LoggerFactory.getLogger(clazz);
    }

    public static void setTransactionContext(String transactionId) {
        MDC.put("transactionId", transactionId);
    }

    public static void clearTransactionContext() {
        MDC.remove("transactionId");
    }

    public static void setUserContext(String userId) {
        MDC.put("userId", userId);
    }

    public static void clearUserContext() {
        MDC.remove("userId");
    }

}
