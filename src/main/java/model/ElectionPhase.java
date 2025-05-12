package model;

/**
 * Represents the different phases of an election in the e-voting system.
 * <p>
 * The election proceeds through these phases in strict sequence:
 * <ol>
 *     <li>SETUP: Initial configuration of the election system</li>
 *     <li>REGISTRATION: Voter registration and certificate issuance</li>
 *     <li>VOTING: Active voting period where ballots are cast</li>
 *     <li>TALLYING: Vote counting and result calculation</li>
 *     <li>CLOSED: Election has concluded</li>
 * </ol>
 * <p>
 * Different election functionality is available or restricted based on the
 * current phase of the election.
 */

public enum ElectionPhase {

    /**
     * Initial configuration phase for setting up the election.
     * During this phase, election parameters are configured and systems initialized.
     */

    SETUP("setup"),

    /**
     * Voter registration phase where eligible voters register and receive certificates.
     * The Registration Authority operates primarily during this phase.
     */

    REGISTRATION("registration"),

    /**
     * Active voting period where authenticated voters submit their ballots.
     * The Voting Server and Ballot Box are active during this phase.
     */

    VOTING("voting"),

    /**
     * Vote tallying phase where results are calculated.
     * The Tallying Authority operates during this phase to decrypt votes and produce results.
     */

    TALLYING("tallying"),

    /**
     * Final phase indicating the election has concluded.
     * No further modifications to the election state are permitted.
     */

    CLOSED("closed");

    private final String phaseName;

    ElectionPhase(String phaseName) {
        this.phaseName = phaseName;
    }

    /**
     * Gets the string representation of the election phase.
     *
     * @return The name of the election phase
     */

    public String getPhaseName() {
        return phaseName;
    }
}
