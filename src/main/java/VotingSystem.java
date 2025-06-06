import core.BallotBox;
import core.RegistrationAuthority;
import core.TallyingAuthority;
import core.VotingServer;
import crypto.MixNetwork;
import exception.AuthenticationException;
import model.*;
import org.slf4j.Logger;
import util.LoggingUtil;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;
import java.util.UUID;

/**
 * Main class that orchestrates the entire e-voting system workflow.
 * <p>
 * This class is responsible for:
 * <ul>
 *     <li>Initializing all system components</li>
 *     <li>Managing the election lifecycle through its different phases</li>
 *     <li>Coordinating the registration, voting, and tallying processes</li>
 *     <li>Handling error conditions and providing logging</li>
 *     <li>Demonstrating the security features of the system</li>
 * </ul>
 * <p>
 * VotingSystem serves as the entry point for the pa-secure-evote application and
 * demonstrates a complete election workflow from setup to results publication.
 */

public class VotingSystem {
    /**
     * Logger for the VotingSystem class, obtained from LoggingUtil.
     */
    private static final Logger logger = LoggingUtil.getLogger(VotingSystem.class);
    /**
     * List of voter IDs used for testing the e-voting system.
     */
    private static final List<String> VOTERS = List.of("Alice", "Bob", "Charlie", "Eve");

    /**
     * Main method that runs the complete e-voting process demonstration.
     * <p>
     * The method:
     * <ol>
     *     <li>Initializes the election manager and system components</li>
     *     <li>Sets up candidates for the election</li>
     *     <li>Implements threshold cryptography for secure vote tallying</li>
     *     <li>Manages the election through its phases (setup, registration, voting, tallying)</li>
     *     <li>Demonstrates voter registration and certificate issuance</li>
     *     <li>Demonstrates vote casting and error handling</li>
     *     <li>Demonstrates certificate revocation</li>
     *     <li>Coordinates vote anonymization through the mix network</li>
     *     <li>Demonstrates threshold decryption and results publication</li>
     * </ol>
     *
     * @param args Command-line arguments
     */

    public static void main(String[] args) {
        try (Scanner sc = new Scanner(System.in)) {
            String sessionId = UUID.randomUUID().toString();
            LoggingUtil.setTransactionContext(sessionId);
            logger.info("Starting e-voting system with session ID: {}", sessionId);

            // Initialize election manager
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

            // Initialize threshold cryptography (3 out of 5 shares needed)
            logger.info("Initializing threshold cryptography for vote tallying");
            tallyingAuthority.splitKey(5, 3);

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
            voter1.setAaPublicKey(tallyingAuthority.getPublicKey());
            voter2.setAaPublicKey(tallyingAuthority.getPublicKey());
            voter3.setAaPublicKey(tallyingAuthority.getPublicKey());

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
            registrationAuthority.exportEligibleVotersList("eligible_voters.txt");

            // Prompt for election closing
            logger.info("Press Enter to close the voting phase and start tallying...");
            sc.nextLine();

            // Transition to tallying phase
            electionManager.transitionTo(ElectionPhase.TALLYING);
            logger.info("System transitioned to tallying phase");

            // Simulate gathering key shares for threshold decryption
            logger.info("Simulating threshold cryptography key reconstruction");
            List<KeyShare> keyShares = tallyingAuthority.getKeyShares().subList(0, 3);

            // Use MixNetwork to anonymize votes before tallying
            logger.info("Anonymizing votes through MixNetwork");
            List<byte[]> encryptedVotes = ballotBox.getEncryptedVotes();

            // Tally votes using the anonymized votes from MixNetwork
            logger.info("Tallying results using threshold cryptography...");
            tallyingAuthority.decryptAndTallyVotes(encryptedVotes, keyShares);

            // Publish results
            tallyingAuthority.publishResults();

            logger.info("E-voting process completed successfully");
        } catch (Exception e) {
            logger.error("Error in the voting process: {}", e.getMessage());
        } finally {
            LoggingUtil.clearTransactionContext();
        }
    }

    /**
     * Attempts to cast a vote with comprehensive error handling.
     * <p>
     * This method:
     * <ol>
     *     <li>Validates that the candidate exists</li>
     *     <li>Attempts to cast a vote for the specified candidate</li>
     *     <li>Handles authentication failures (including duplicate voting attempts)</li>
     *     <li>Handles other unexpected exceptions during the voting process</li>
     * </ol>
     *
     * @param voter The voter attempting to cast a vote
     * @param votingServer The voting server for authentication
     * @param ballotBox The ballot box for vote submission
     * @param candidateManager The candidate manager for candidate validation
     * @param candidateName The name of the candidate the voter is voting for
     */

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

    /**
     * Tests the system's security by attempting to cast a vote with an ineligible voter.
     * <p>
     * This method demonstrates how the system handles unauthorized voting attempts,
     * which is an important security feature of the e-voting system.
     * <p>
     * Sets a special "SecurityAudit" user context for logging these
     * security events.
     *
     * @param ra The registration authority
     * @param sv The voting server
     * @param ue The ballot box
     * @param aa The tallying authority
     * @param candidateManager The candidate manager
     */

    private static void testIneligibleVoter(RegistrationAuthority ra, VotingServer sv, BallotBox ue,
                                            TallyingAuthority aa, CandidateManager candidateManager) {
        LoggingUtil.setUserContext("SecurityAudit");
        try {
            Voter ineligibleVoter = new Voter(VOTERS.get(3));
            ineligibleVoter.registerWithRA(ra);
            ineligibleVoter.setAaPublicKey(aa.getPublicKey());

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

    /**
     * Creates a sample candidates configuration file if it doesn't
     * already exist.
     * <p>
     * The file contains a list of candidates, one per line, with comments
     * preceded by '#' characters.
     *
     * @param filename The name of the candidates file to create
     */

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
