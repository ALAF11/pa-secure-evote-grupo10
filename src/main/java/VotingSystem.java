import core.RegistrationAuthority;
import core.VotingServer;
import model.ElectionManager;
import model.ElectionPhase;
import model.Voter;
import org.slf4j.Logger;
import util.LoggingUtil;

import java.util.List;
import java.util.Scanner;
import java.util.UUID;

public class VotingSystem {
    private static final Logger logger = LoggingUtil.getLogger(VotingSystem.class);
    private static final List<String > VOTERS = List.of("Alice", "Bob", "Charlie", "Eve");

    public static void main (String[] args) {
        try(Scanner sc = new Scanner(System.in)) {
            String sessionId = UUID.randomUUID().toString();
            LoggingUtil.setTransactionContext(sessionId);
            logger.info("Starting e-voting system with session ID: {}", sessionId);

            ElectionManager electionManager = new ElectionManager();

            RegistrationAuthority registrationAuthority = new RegistrationAuthority(electionManager);
            VotingServer votingServer = new VotingServer(registrationAuthority.getPublicKey(), electionManager, registrationAuthority.getCrl());

            // Start with setup phase
            logger.info("System is in setup phase");

            // Transition to registration phase
            electionManager.transitionTo(ElectionPhase.REGISTRATION);
            logger.info("System transitioned to registration phase");



            // Create and register voters
            Voter voter1 = new Voter(VOTERS.get(0));
            Voter voter2 = new Voter(VOTERS.get(1));
            Voter voter3 = new Voter(VOTERS.get(2));

            // Register eligible voters with the Registration Authority
            registrationAuthority.registerEligibleVoter(VOTERS.get(0));
            registrationAuthority.registerEligibleVoter(VOTERS.get(1));
            registrationAuthority.registerEligibleVoter(VOTERS.get(2));
            logger.info("Registered eligible voters with Registration Authority");

            // Register voters with the RA to get certificates
            voter1.registerWithRA(registrationAuthority);
            voter2.registerWithRA(registrationAuthority);
            voter3.registerWithRA(registrationAuthority);

            registrationAuthority.exportEligibleVotersList("eligible_voters.txt");

            registrationAuthority.shareEligibleVotersListWithVotingServer(votingServer);


        }
        catch (Exception e) {
            logger.error("Error in the voting process: {}", e.getMessage());
        }
        finally {
            LoggingUtil.clearTransactionContext();
        }
    }

}
