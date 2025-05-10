package model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ElectionPhaseTest {

    @Test
    @DisplayName("Verifies that all expected election phases exist in the enum")
    public void testElectionPhasesValues() {
        ElectionPhase[] phases = ElectionPhase.values();
        assertEquals(5, phases.length);
        assertEquals(ElectionPhase.SETUP, phases[0]);
        assertEquals(ElectionPhase.REGISTRATION, phases[1]);
        assertEquals(ElectionPhase.VOTING, phases[2]);
        assertEquals(ElectionPhase.TALLYING, phases[3]);
        assertEquals(ElectionPhase.CLOSED, phases[4]);
    }

    @Test
    @DisplayName("Tests that each phase has the correct name value")
    public void testPhaseNames() {
        assertEquals("setup", ElectionPhase.SETUP.getPhaseName());
        assertEquals("registration", ElectionPhase.REGISTRATION.getPhaseName());
        assertEquals("voting", ElectionPhase.VOTING.getPhaseName());
        assertEquals("tallying", ElectionPhase.TALLYING.getPhaseName());
        assertEquals("closed", ElectionPhase.CLOSED.getPhaseName());
    }

    @Test
    @DisplayName("Verifies valueOf() method works correctly for enum conversion")
    public void testValueOf() {
        assertEquals(ElectionPhase.SETUP, ElectionPhase.valueOf("SETUP"));
        assertEquals(ElectionPhase.REGISTRATION, ElectionPhase.valueOf("REGISTRATION"));
        assertEquals(ElectionPhase.VOTING, ElectionPhase.valueOf("VOTING"));
        assertEquals(ElectionPhase.TALLYING, ElectionPhase.valueOf("TALLYING"));
        assertEquals(ElectionPhase.CLOSED, ElectionPhase.valueOf("CLOSED"));
    }

}