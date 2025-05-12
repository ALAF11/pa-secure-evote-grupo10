package model;

import org.slf4j.Logger;
import util.LoggingUtil;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Manages the election phases and transitions in the e-voting system.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Tracking the current phase of the election</li>
 *     <li>Enforcing proper phase transitions</li>
 *     <li>Recording timestamps of phase transitions</li>
 *     <li>Providing phase status information to other components</li>
 * </ul>
 * <p>
 * The election progresses through five distinct phases:
 * SETUP → REGISTRATION → VOTING → TALLYING → CLOSED
 * <p>
 * Thread-safe implementation using AtomicReference to manage concurrent access
 * to phase information.
 */

public class ElectionManager {
    private static final Logger logger = LoggingUtil.getLogger(ElectionManager.class);

    private final AtomicReference<ElectionPhase> currentPhase =
            new AtomicReference<>(ElectionPhase.SETUP);
    private final AtomicReference<Instant> phaseStartTime =
            new AtomicReference<>(Instant.now());

    /**
     * Transitions the election to a new phase.
     * <p>
     * This method enforces a valid phase sequence:
     * SETUP → REGISTRATION → VOTING → TALLYING → CLOSED
     * <p>
     * If an invalid transition is attempted, the method will log a warning
     * and the phase will remain unchanged.
     *
     * @param newPhase The phase to transition to
     */

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

    /**
     * Determines whether a transition from one phase to another is valid.
     * <p>
     * Valid transitions follow the sequence:
     * SETUP → REGISTRATION → VOTING → TALLYING → CLOSED
     *
     * @param from The current phase
     * @param to The target phase
     * @return true if the transition is valid, false otherwise
     */

    private boolean isValidTransition(ElectionPhase from, ElectionPhase to) {
        return switch (from) {
            case SETUP -> to == ElectionPhase.REGISTRATION;
            case REGISTRATION -> to == ElectionPhase.VOTING;
            case VOTING -> to == ElectionPhase.TALLYING;
            case TALLYING -> to == ElectionPhase.CLOSED;
            case CLOSED -> false;
        };
    }

    /**
     * Checks if the election is currently in the specified phase.
     *
     * @param phase The phase to check against the current phase
     * @return true if the current phase matches the specified phase, false otherwise
     */

    public boolean isInPhase(ElectionPhase phase) {
        return currentPhase.get() == phase;
    }
}
