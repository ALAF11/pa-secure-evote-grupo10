package core;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.quality.Strictness;
import org.mockito.junit.jupiter.MockitoSettings;

import crypto.CertificateRevocationList;
import exception.AuthenticationException;
import model.ElectionManager;
import model.ElectionPhase;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class VotingServerTest {

    private VotingServer votingServer;

    @Mock
    private PublicKey raPublicKey;

    @Mock
    private ElectionManager electionManager;

    @Mock
    private CertificateRevocationList crl;

    @Mock
    private X509Certificate validCertificate;

    private PublicKey aaPublicKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        // Create test public key
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        aaPublicKey = keyPair.getPublic();

        // Initialize voting server
        votingServer = new VotingServer(raPublicKey, electionManager, crl);

        // Set up certificate mock to return valid voter ID
        X500Principal principal = mock(X500Principal.class);
        when(validCertificate.getSubjectX500Principal()).thenReturn(principal);
        when(principal.getName()).thenReturn("CN=validVoter");
    }

    @Test
    @DisplayName("Should store eligible voters when updating the voters list")
    void updateEligibleVotersList_ShouldStoreVoters() {

        Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
        eligibleVoters.put("voter1", true);
        eligibleVoters.put("voter2", true);


        votingServer.updateEligibleVotersList(eligibleVoters);
    }

    @Test
    @DisplayName("Should return a valid token when authenticating an eligible voter during voting phase")
    void authenticateVoter_ValidVoterDuringVotingPhase_ShouldReturnToken() throws Exception {

        Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
        eligibleVoters.put("validVoter", true);
        votingServer.updateEligibleVotersList(eligibleVoters);

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);
        when(crl.isRevoked(validCertificate)).thenReturn(false);

        // Make certificate validation pass
        doNothing().when(validCertificate).verify(raPublicKey);
        doNothing().when(validCertificate).checkValidity();


        String token = votingServer.authenticateVoter(validCertificate);


        assertNotNull(token);
        assertTrue(votingServer.validateToken(token));
    }

    @Test
    @DisplayName("Should throw exception when authenticating outside of voting phase")
    void authenticateVoter_OutsideVotingPhase_ShouldThrowException() {

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(false);


        Exception exception = assertThrows(AuthenticationException.class, () -> {
            votingServer.authenticateVoter(validCertificate);
        });
        assertTrue(exception.getMessage().contains("not currently active"));
    }

    @Test
    @DisplayName("Should throw exception when authenticating an ineligible voter")
    void authenticateVoter_IneligibleVoter_ShouldThrowException() {

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);


        Exception exception = assertThrows(AuthenticationException.class, () -> {
            votingServer.authenticateVoter(validCertificate);
        });
        assertTrue(exception.getMessage().contains("not eligible"));
    }

    @Test
    @DisplayName("Should throw exception when authenticating with a revoked certificate")
    void authenticateVoter_RevokedCertificate_ShouldThrowException() {

        Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
        eligibleVoters.put("validVoter", true);
        votingServer.updateEligibleVotersList(eligibleVoters);

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);
        when(crl.isRevoked(validCertificate)).thenReturn(true);


        Exception exception = assertThrows(AuthenticationException.class, () -> {
            votingServer.authenticateVoter(validCertificate);
        });
        assertTrue(exception.getMessage().contains("revoked"));
    }

    @Test
    @DisplayName("Should throw exception when authenticating with an invalid certificate")
    void authenticateVoter_InvalidCertificate_ShouldThrowException() throws Exception {

        Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
        eligibleVoters.put("validVoter", true);
        votingServer.updateEligibleVotersList(eligibleVoters);

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);
        when(crl.isRevoked(validCertificate)).thenReturn(false);


        doThrow(new SignatureException("Invalid certificate"))
                .when(validCertificate).verify(raPublicKey);

        Exception exception = assertThrows(AuthenticationException.class, () -> {
            votingServer.authenticateVoter(validCertificate);
        });
        assertTrue(exception.getMessage().contains("Invalid certificate"));
    }

    @Test
    @DisplayName("Should throw exception when a voter attempts to vote more than once")
    void authenticateVoter_AlreadyVoted_ShouldThrowException() throws Exception {

        Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
        eligibleVoters.put("validVoter", true);
        votingServer.updateEligibleVotersList(eligibleVoters);

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);
        when(crl.isRevoked(validCertificate)).thenReturn(false);

        // Make certificate validation pass
        doNothing().when(validCertificate).verify(raPublicKey);
        doNothing().when(validCertificate).checkValidity();

        // First authentication to mark as voted
        String token = votingServer.authenticateVoter(validCertificate);


        AuthenticationException exception = assertThrows(AuthenticationException.class, () -> {
            votingServer.authenticateVoter(validCertificate);
        });

        assertNotNull(exception);
    }

    @Test
    @DisplayName("Should return true when validating a valid token")
    void validateToken_ValidToken_ShouldReturnTrue() throws Exception {

        Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
        eligibleVoters.put("validVoter", true);
        votingServer.updateEligibleVotersList(eligibleVoters);

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);
        when(crl.isRevoked(validCertificate)).thenReturn(false);
        doNothing().when(validCertificate).verify(raPublicKey);
        doNothing().when(validCertificate).checkValidity();

        String token = votingServer.authenticateVoter(validCertificate);


        assertTrue(votingServer.validateToken(token));
    }

    @Test
    @DisplayName("Should return false when validating an invalid token")
    void validateToken_InvalidToken_ShouldReturnFalse() {

        assertFalse(votingServer.validateToken("invalidToken"));
    }

    @Test
    @DisplayName("Should remove token when marking it as used")
    void markTokenAsUsed_ShouldRemoveToken() throws Exception {

        Map<String, Boolean> eligibleVoters = new ConcurrentHashMap<>();
        eligibleVoters.put("validVoter", true);
        votingServer.updateEligibleVotersList(eligibleVoters);

        when(electionManager.isInPhase(ElectionPhase.VOTING)).thenReturn(true);
        when(crl.isRevoked(validCertificate)).thenReturn(false);
        doNothing().when(validCertificate).verify(raPublicKey);
        doNothing().when(validCertificate).checkValidity();

        String token = votingServer.authenticateVoter(validCertificate);
        assertTrue(votingServer.validateToken(token));


        votingServer.markTokenAsUsed(token);

        assertFalse(votingServer.validateToken(token));
    }

    @Test
    @DisplayName("Should correctly set and get the Tallying Authority public key")
    void setGetAaPublicKey_ShouldWorkCorrectly() {

        votingServer.setAaPublicKey(aaPublicKey);

        assertEquals(aaPublicKey, votingServer.getAaPublicKey());
    }
}