package model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CandidateManagerTest {

    private CandidateManager candidateManager;

    @BeforeEach
    void setUp() {
        candidateManager = new CandidateManager();
    }

    @Test
    @DisplayName("Test adding and retrieving candidates")
    void testAddCandidate() {

        String candidate1 = "candidate1";
        String candidate2 = "candidate2";


        candidateManager.addCandidate(candidate1);
        candidateManager.addCandidate(candidate2);
        List<String> candidates = candidateManager.getCandidates();


        assertEquals(2, candidates.size());
        assertTrue(candidates.contains(candidate1));
        assertTrue(candidates.contains(candidate2));
    }

    @Test
    @DisplayName("Test validating candidate names")
    void testIsValidCandidate() {

        String validCandidate = "candidate1";
        String invalidCandidate = "Unknown Person";
        candidateManager.addCandidate(validCandidate);


        assertTrue(candidateManager.isValidCandidate(validCandidate));
        assertFalse(candidateManager.isValidCandidate(invalidCandidate));
    }

    @Test
    @DisplayName("Test loading candidates from file")
    void testLoadCandidatesFromFile(@TempDir Path tempDir) throws Exception {

        File testFile = tempDir.resolve("candidates.txt").toFile();
        try (FileWriter writer = new FileWriter(testFile)) {
            writer.write("# Test candidates file\n");
            writer.write("Candidate1\n");
            writer.write("Candidate2\n");
            writer.write("Candidate3\n");
        }


        boolean result = candidateManager.loadCandidatesFromFile(testFile.getPath());


        assertTrue(result);
        assertEquals(3, candidateManager.getCandidates().size());
        assertTrue(candidateManager.isValidCandidate("Candidate1"));
        assertTrue(candidateManager.isValidCandidate("Candidate2"));
        assertTrue(candidateManager.isValidCandidate("Candidate3"));
    }
}
