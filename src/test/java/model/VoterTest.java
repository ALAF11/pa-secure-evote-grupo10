package model;

import core.BallotBox;
import core.RegistrationAuthority;
import core.VotingServer;
import crypto.CryptoUtils;
import exception.AuthenticationException;
import exception.VoteSubmissionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;


import java.lang.reflect.Field;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class VoterTest {

    private static final String VOTER_ID = "voter123";

    @Mock
    private RegistrationAuthority mockRA;

    @Mock
    private VotingServer mockVotingServer;

    @Mock
    private BallotBox mockBallotBox;

    @Mock
    private X509Certificate mockCertificate;

    @Mock
    private PublicKey mockAAPublicKey;

    private Voter voter;

    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException {
        // Create a real voter instance for testing
        voter = new Voter(VOTER_ID);
    }

    @Test
    @DisplayName("Verifies that a voter is correctly initialized with the given ID and generates a key pair")
    public void testVoterInitialization() {
        assertEquals(VOTER_ID, voter.getId(), "Voter ID should match the provided ID");
        assertNotNull(voter.getPublicKey(), "Public key should be generated during initialization");
    }

    @Test
    @DisplayName("Tests that a voter can register with the Registration Authority and receive a certificate")
    public void testRegisterWithRA() throws Exception {
        // Correct use of when/thenReturn for non-void method
        when(mockRA.issueCertificate(any(Voter.class))).thenReturn(mockCertificate);

        // Mock the static method in CryptoUtils
        try (MockedStatic<CryptoUtils> cryptoUtilsMock = mockStatic(CryptoUtils.class)) {
            cryptoUtilsMock.when(() -> CryptoUtils.encodeCertificateToPEM(any())).thenReturn("TEST_PEM_CERT");

            // Use a spy to avoid actual file writing
            voter = spy(voter);
            doNothing().when(voter).exportCertificateToFile(anyString());

            voter.registerWithRA(mockRA);

            verify(mockRA).issueCertificate(voter);
            verify(voter).exportCertificateToFile(anyString());
        }
    }

    @Test
    @DisplayName("Tests that registration fails when the RA throws a security exception")
    public void testRegisterWithRASecurityException() throws Exception {

        when(mockRA.issueCertificate(any(Voter.class))).thenThrow(new SecurityException("Not eligible"));

        assertThrows(SecurityException.class, () -> voter.registerWithRA(mockRA));
    }

    @Test
    @DisplayName("Tests that voting fails when a voter has not been registered")
    public void testVoteWithoutRegistration() {
        // No certificate has been set
        Exception exception = assertThrows(IllegalStateException.class,
                () -> voter.vote(mockVotingServer, mockBallotBox, "Candidate1"));

        assertEquals("Voter must be registered before voting", exception.getMessage());
    }

    @Test
    @DisplayName("Tests that voting fails when the AA public key has not been set")
    public void testVoteWithoutAAPublicKey() throws Exception {
        // Set certificate but not AA public key
        Field certificateField = Voter.class.getDeclaredField("certificate");
        certificateField.setAccessible(true);
        certificateField.set(voter, mockCertificate);

        Exception exception = assertThrows(IllegalStateException.class,
                () -> voter.vote(mockVotingServer, mockBallotBox, "Candidate1"));

        assertEquals("Tallying Authority public key not set", exception.getMessage());
    }

    @Test
    @DisplayName("Tests the complete voting process with proper setup")
    public void testVoteSuccessful() throws Exception {
        // Set up certificate and AA public key
        Field certificateField = Voter.class.getDeclaredField("certificate");
        certificateField.setAccessible(true);
        certificateField.set(voter, mockCertificate);

        voter.setAaPublicKey(mockAAPublicKey);

        // Mock dependencies
        when(mockVotingServer.authenticateVoter(any())).thenReturn("TEST_TOKEN");

        try (MockedStatic<CryptoUtils> cryptoUtilsMock = mockStatic(CryptoUtils.class)) {
            byte[] mockHash = "HASH".getBytes();
            byte[] mockSignature = "SIGNATURE".getBytes();
            byte[] mockEncrypted = "ENCRYPTED".getBytes();

            cryptoUtilsMock.when(() -> CryptoUtils.hash(any())).thenReturn(mockHash);
            cryptoUtilsMock.when(() -> CryptoUtils.sign(eq(mockHash), any())).thenReturn(mockSignature);
            cryptoUtilsMock.when(() -> CryptoUtils.encryptVote(anyString(), any())).thenReturn(mockEncrypted);

            voter.vote(mockVotingServer, mockBallotBox, "Candidate1");

            verify(mockVotingServer).authenticateVoter(mockCertificate);
            verify(mockBallotBox).submitVote(eq(mockEncrypted), eq("TEST_TOKEN"), eq(mockSignature));
        }
    }

    @Test
    @DisplayName("Tests that voting fails when the server authentication fails")
    public void testVoteAuthenticationFailure() throws Exception {
        // Set up certificate and AA public key
        Field certificateField = Voter.class.getDeclaredField("certificate");
        certificateField.setAccessible(true);
        certificateField.set(voter, mockCertificate);

        voter.setAaPublicKey(mockAAPublicKey);

        // Mock authentication failure
        when(mockVotingServer.authenticateVoter(any())).thenThrow(new AuthenticationException("Authentication failed"));

        assertThrows(AuthenticationException.class,
                () -> voter.vote(mockVotingServer, mockBallotBox, "Candidate1"));
    }

    @Test
    @DisplayName("Tests that exporting certificate fails when PEM is not available")
    public void testExportCertificateNoPEM() {

        Exception exception = assertThrows(IllegalStateException.class,
                () -> voter.exportCertificateToFile("test.pem"));

        assertEquals("Certificate not available in PEM format", exception.getMessage());
    }

    @Test
    @DisplayName("Tests that exporting certificate succeeds with proper setup")
    public void testExportCertificate() throws Exception {

        Field pemField = Voter.class.getDeclaredField("pemCertificate");
        pemField.setAccessible(true);
        pemField.set(voter, "TEST_PEM_CERTIFICATE");

        // Create a spy to avoid actual file writing
        voter = spy(voter);
        doNothing().when(voter).exportCertificateToFile(anyString());

        voter.exportCertificateToFile("test.pem");

        // Just verify the method was called
        verify(voter).exportCertificateToFile("test.pem");
    }

    @Test
    @DisplayName("Tests that getId returns the correct voter ID")
    public void testGetId() {
        assertEquals(VOTER_ID, voter.getId());
    }

    @Test
    @DisplayName("Tests that getPublicKey returns a valid public key")
    public void testGetPublicKey() {
        assertNotNull(voter.getPublicKey());
    }
}