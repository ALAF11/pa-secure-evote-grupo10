package model;

import org.slf4j.Logger;
import util.LoggingUtil;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

public class ElectionManager {
    private static final Logger logger = LoggingUtil.getLogger(ElectionManager.class);

    private final AtomicReference<ElectionPhase> currentPhase =
            new AtomicReference<>(ElectionPhase.SETUP);
    private final AtomicReference<Instant> phaseStartTime =
            new AtomicReference<>(Instant.now());

    public void transitionTo(ElectionPhase newPhase) {
        ElectionPhase currentPhaseLoc = this.currentPhase.get();

        if (!isValidTransition(currentPhaseLoc, newPhase)) {
            logger.warn("Invalid phase transition from {} to {}",
                    currentPhaseLoc, newPhase);
            return;
        }

        boolean success = this.currentPhase.compareAndSet(currentPhaseLoc, newPhase);
        if (success) {
            Instant now = Instant.now();
            phaseStartTime.set(now);
            logger.info("Election phase changed from {} to {} at {}",
                    currentPhaseLoc, newPhase, now);
        }
    }

    private boolean isValidTransition(ElectionPhase from, ElectionPhase to) {
        return switch (from) {
            case SETUP -> to == ElectionPhase.REGISTRATION;
            case REGISTRATION -> to == ElectionPhase.VOTING;
            case VOTING -> to == ElectionPhase.TALLYING;
            case TALLYING -> to == ElectionPhase.CLOSED;
            case CLOSED -> false;
        };
    }

    public boolean isInPhase(ElectionPhase phase) {
        return currentPhase.get() == phase;
    }
}
