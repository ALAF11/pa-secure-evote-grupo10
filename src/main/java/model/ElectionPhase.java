package model;

public enum ElectionPhase {
    SETUP("setup"),
    REGISTRATION("registration"),
    VOTING("voting"),
    TALLYING("tallying"),
    CLOSED("closed");

    private final String phaseName;

    ElectionPhase(String phaseName) {
        this.phaseName = phaseName;
    }

    public String getPhaseName() {
        return phaseName;
    }
}
