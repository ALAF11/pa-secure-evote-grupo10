package model;

import static org.junit.jupiter.api.Assertions.*;

import model.ElectionManager;
import model.ElectionPhase;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;

public class ElectionManagerTest {

    private ElectionManager electionManager;

    @BeforeEach
    public void setUp() {
        electionManager = new ElectionManager();
    }

    @Test
    @DisplayName("Verifies that the initial phase is SETUP")
    public void testInitialPhase() {
        assertTrue(electionManager.isInPhase(ElectionPhase.SETUP));
    }

    @Test
    @DisplayName("Tests all valid phase transitions in sequence")
    public void testValidPhaseTransitions() {
        // Start in SETUP
        assertTrue(electionManager.isInPhase(ElectionPhase.SETUP));

        // SETUP -> REGISTRATION
        electionManager.transitionTo(ElectionPhase.REGISTRATION);
        assertTrue(electionManager.isInPhase(ElectionPhase.REGISTRATION));

        // REGISTRATION -> VOTING
        electionManager.transitionTo(ElectionPhase.VOTING);
        assertTrue(electionManager.isInPhase(ElectionPhase.VOTING));

        // VOTING -> TALLYING
        electionManager.transitionTo(ElectionPhase.TALLYING);
        assertTrue(electionManager.isInPhase(ElectionPhase.TALLYING));

        // TALLYING -> CLOSED
        electionManager.transitionTo(ElectionPhase.CLOSED);
        assertTrue(electionManager.isInPhase(ElectionPhase.CLOSED));
    }

    @Test
    @DisplayName("Tests that invalid phase transitions are rejected")
    public void testInvalidPhaseTransitions() {
        // Try to skip from SETUP to VOTING (should fail)
        electionManager.transitionTo(ElectionPhase.VOTING);
        assertTrue(electionManager.isInPhase(ElectionPhase.SETUP));

        // Proper transition to REGISTRATION
        electionManager.transitionTo(ElectionPhase.REGISTRATION);
        assertTrue(electionManager.isInPhase(ElectionPhase.REGISTRATION));

        // Try to transition to TALLYING (skipping VOTING, should fail)
        electionManager.transitionTo(ElectionPhase.TALLYING);
        assertTrue(electionManager.isInPhase(ElectionPhase.REGISTRATION));

        // Complete the normal sequence
        electionManager.transitionTo(ElectionPhase.VOTING);
        electionManager.transitionTo(ElectionPhase.TALLYING);
        electionManager.transitionTo(ElectionPhase.CLOSED);

        // Try to transition from CLOSED (should fail)
        electionManager.transitionTo(ElectionPhase.SETUP);
        assertTrue(electionManager.isInPhase(ElectionPhase.CLOSED));
    }

    @Test
    @DisplayName("Verifies the isInPhase method correctly identifies the current phase")
    public void testIsInPhase() {
        assertTrue(electionManager.isInPhase(ElectionPhase.SETUP));
        assertFalse(electionManager.isInPhase(ElectionPhase.REGISTRATION));
        assertFalse(electionManager.isInPhase(ElectionPhase.VOTING));
        assertFalse(electionManager.isInPhase(ElectionPhase.TALLYING));
        assertFalse(electionManager.isInPhase(ElectionPhase.CLOSED));

        electionManager.transitionTo(ElectionPhase.REGISTRATION);
        assertFalse(electionManager.isInPhase(ElectionPhase.SETUP));
        assertTrue(electionManager.isInPhase(ElectionPhase.REGISTRATION));
        assertFalse(electionManager.isInPhase(ElectionPhase.VOTING));
    }

    @Test
    @DisplayName("Tests that phase start time is updated on transition")
    public void testPhaseStartTimeUpdates() throws Exception {
        // Get initial start time using reflection (for testing purposes)
        Field phaseStartTimeField = ElectionManager.class.getDeclaredField("phaseStartTime");
        phaseStartTimeField.setAccessible(true);
        Instant initialTime = (Instant)((AtomicReference)phaseStartTimeField.get(electionManager)).get();

        // Sleep briefly to ensure time difference
        Thread.sleep(10);

        // Make a transition
        electionManager.transitionTo(ElectionPhase.REGISTRATION);

        // Check that time was updated
        Instant newTime = (Instant)((AtomicReference)phaseStartTimeField.get(electionManager)).get();
        assertTrue(newTime.isAfter(initialTime));
    }
}
