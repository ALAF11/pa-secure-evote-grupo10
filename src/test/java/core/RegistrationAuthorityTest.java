package core;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import model.ElectionManager;
import model.ElectionPhase;
import model.Voter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;


//Uses Mockito to create mocks for the ElectionManager and Voter classes
@ExtendWith(MockitoExtension.class)
public class RegistrationAuthorityTest {

    private RegistrationAuthority registrationAuthority;

    @Mock
    private ElectionManager electionManager;

    @Mock
    private Voter voter;

    private KeyPair voterKeyPair;

    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException {
        //Set up mock behavior for ElectionManager

        lenient().when(electionManager.isInPhase(ElectionPhase.REGISTRATION)).thenReturn(true);

        //Initialize RegistrationAuthority with mock ElectionManager
        registrationAuthority = new RegistrationAuthority(electionManager);

        //Generate a key Pair for the mock voter
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        voterKeyPair = keyGenerator.generateKeyPair();

        // Set up mock voter behavior
        lenient().when(voter.getId()).thenReturn("voter123");
        lenient().when(voter.getPublicKey()).thenReturn(voterKeyPair.getPublic());
    }

    @Test
    @DisplayName("Verifies that eligible voters can be registered successfully during registration phase")
    public void testRegisterEligibleVoter() {

        boolean result = registrationAuthority.registerEligibleVoter("voter123");

        assertTrue(result);

        //test duplicate registration
        boolean duplicateResult = registrationAuthority.registerEligibleVoter("voter123");
        assertFalse(duplicateResult);

    }

    @Test
    @DisplayName("Tests that voter registration fails outside of registration phase")
    public void testRegisterEligibleVoterOutsidePhase() {
        when(electionManager.isInPhase(ElectionPhase.REGISTRATION)).thenReturn(false);

        assertThrows(IllegalStateException.class, () -> {
            registrationAuthority.registerEligibleVoter("voter123");
        });
    }

    @Test
    @DisplayName("Verifies that eligible voters can be removed successfully")
    public void testRemoveEligibleVoter() {

        registrationAuthority.registerEligibleVoter("voter123");

        boolean result = registrationAuthority.removeEligibleVoter("voter123");

        assertTrue(result);

        //test removing non-existent voter
        boolean nonExistentResult = registrationAuthority.removeEligibleVoter("nonexistent");
        assertFalse(nonExistentResult);
    }

    @Test
    @DisplayName("Tests certificate issuance for eligible voters")
    public void testIssueCertificate() throws Exception {

        registrationAuthority.registerEligibleVoter("voter123");

        X509Certificate certificate = registrationAuthority.issueCertificate(voter);

        assertNotNull(certificate);
        assertEquals("CN=voter123", certificate.getSubjectX500Principal().getName());

        //verify certificate signature
        certificate.verify(registrationAuthority.getPublicKey());
    }

    @Test
    @DisplayName("Tests certificate issuance fails for ineligible voters")
    public void testIssueCertificateIneligibleVoter() {
        assertThrows(SecurityException.class, () -> {
            registrationAuthority.issueCertificate(voter);
        });
    }

    @Test
    @DisplayName("Tests certificate issuance fails outside registration phase")
    public void testIssueCertificateOutsidePhase() {

        registrationAuthority.registerEligibleVoter("voter123");

        when(electionManager.isInPhase(ElectionPhase.REGISTRATION)). thenReturn(false);

        assertThrows(IllegalStateException.class, () -> {
            registrationAuthority.issueCertificate(voter);
        });
    }

    @Test
    @DisplayName("Verifies the RA public key is correctly returned")
    public void testGetPublicKey() {

        assertNotNull(registrationAuthority.getPublicKey());

    }




}