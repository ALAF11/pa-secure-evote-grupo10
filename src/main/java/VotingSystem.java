import core.BallotBox;
import core.RegistrationAuthority;
import core.TallyingAuthority;
import core.VotingServer;
import crypto.MixNetwork;
import exception.AuthenticationException;
import model.CandidateManager;
import model.ElectionManager;
import model.ElectionPhase;
import model.Voter;
import org.slf4j.Logger;
import util.LoggingUtil;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

public class VotingSystem {
    private static final Logger logger = LoggingUtil.getLogger(VotingSystem.class);
    private static final List<String> VOTERS = List.of("Alice", "Bob", "Charlie", "Eve");

    public static void main(String[] args) {
        try (Scanner sc = new Scanner(System.in)) {
            String sessionId = UUID.randomUUID().toString();
            LoggingUtil.setTransactionContext(sessionId);
            logger.info("Starting e-voting system with session ID: {}", sessionId);

            ElectionManager electionManager = new ElectionManager();

            // Initialize system components
            RegistrationAuthority registrationAuthority = new RegistrationAuthority(electionManager);
            VotingServer votingServer = new VotingServer(registrationAuthority.getPublicKey(),
                    electionManager,
                    registrationAuthority.getCrl());

            TallyingAuthority tallyingAuthority = new TallyingAuthority();
            MixNetwork mixNetwork = new MixNetwork(tallyingAuthority.getPublicKey());
            BallotBox ballotBox = new BallotBox(votingServer, mixNetwork, electionManager);

            // Initialize candidate manager and load candidates
            CandidateManager candidateManager = new CandidateManager();
            // Create sample candidates file if it doesn't exist
            createSampleCandidatesFile("candidates.txt");

            if (!candidateManager.loadCandidatesFromFile("candidates.txt")) {
                logger.warn("Failed to load candidates from file, using default candidates");
                candidateManager.addCandidate("Candidate1");
                candidateManager.addCandidate("Candidate2");
            }

            // Share AA's public key with the voting server
            votingServer.setAaPublicKey(tallyingAuthority.getPublicKey());

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

            // Export eligible voters list to a file for reference
            registrationAuthority.exportEligibleVotersList("eligible_voters.txt");

            // Share eligible voters list with voting server
            registrationAuthority.shareEligibleVotersListWithVotingServer(votingServer);

            // Set AA's public key with voters for vote encryption
            voter1.setAAPublicKey(tallyingAuthority.getPublicKey());
            voter2.setAAPublicKey(tallyingAuthority.getPublicKey());
            voter3.setAAPublicKey(tallyingAuthority.getPublicKey());

            // Transition to voting phase
            electionManager.transitionTo(ElectionPhase.VOTING);
            logger.info("System transitioned to voting phase");

            // Voting process with proper candidate validation and error handling
            castVoteWithErrorHandling(voter1, votingServer, ballotBox, candidateManager, "Candidate1");
            castVoteWithErrorHandling(voter2, votingServer, ballotBox, candidateManager, "Candidate2");
            castVoteWithErrorHandling(voter3, votingServer, ballotBox, candidateManager, "Candidate1");

            // This should now fail properly with "Voter has already cast a vote" error
            castVoteWithErrorHandling(voter1, votingServer, ballotBox, candidateManager, "Candidate2");

            // Try with an ineligible voter
            testIneligibleVoter(registrationAuthority, votingServer, ballotBox, tallyingAuthority, candidateManager);

            // Certificate revocation example
            logger.info("Testing certificate revocation functionality");
            registrationAuthority.revokeCertificate(voter3.getCertificateSerialNumber(), "Voter requested revocation");
            registrationAuthority.removeEligibleVoter(VOTERS.get(2));
            registrationAuthority.shareEligibleVotersListWithVotingServer(votingServer);

            // Prompt for election closing
            logger.info("Press Enter to close the voting phase and start tallying...");
            sc.nextLine();

        } catch (Exception e) {
            logger.error("Error in the voting process: {}", e.getMessage());
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

    private static void castVoteWithErrorHandling(Voter voter, VotingServer votingServer,
                                                  BallotBox ballotBox, CandidateManager candidateManager,
                                                  String candidateName) {
        try {
            // Validate candidate first
            if (!candidateManager.isValidCandidate(candidateName)) {
                logger.warn("Invalid candidate choice: {}", candidateName);
                return;
            }

            voter.vote(votingServer, ballotBox, candidateName);
        } catch (AuthenticationException e) {
            // Handle authentication failures (including duplicate voting)
            logger.warn("Vote failed for voter {}: {}", voter.getId(), e.getMessage());
        } catch (Exception e) {
            // Handle other exceptions
            logger.error("Unexpected error during voting for {}: {}", voter.getId(), e.getMessage());
        }
    }

    private static void testIneligibleVoter(RegistrationAuthority ra, VotingServer sv, BallotBox ue,
                                            TallyingAuthority aa, CandidateManager candidateManager) {
        LoggingUtil.setUserContext("SecurityAudit");
        try {
            Voter ineligibleVoter = new Voter(VOTERS.get(3));
            ineligibleVoter.registerWithRA(ra);
            ineligibleVoter.setAAPublicKey(aa.getPublicKey());

            if (candidateManager.isValidCandidate("Candidate3")) {
                ineligibleVoter.vote(sv, ue, "Candidate3");
            } else {
                ineligibleVoter.vote(sv, ue, candidateManager.getCandidates().get(0));
            }
        } catch (Exception e) {
            logger.error("Prevented ineligible voter from voting: {}", e.getMessage());
        } finally {
            LoggingUtil.clearUserContext();
        }
    }

    private static void createSampleCandidatesFile(String filename) {
        File file = new File(filename);
        if (!file.exists()) {
            try (FileWriter writer = new FileWriter(file)) {
                writer.write("# Candidate list configuration file\n");
                writer.write("Candidate1\n");
                writer.write("Candidate2\n");
                writer.write("Candidate3\n");
                logger.info("Created sample candidates file: {}", filename);
            } catch (IOException e) {
                logger.error("Failed to create sample candidates file: {}", e.getMessage());
            }
        }
    }
}
