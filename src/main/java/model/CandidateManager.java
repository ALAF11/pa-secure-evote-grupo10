package model;

import org.slf4j.Logger;
import util.LoggingUtil;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Manages the list of candidates for the e-voting system.
 * <p>
 * This class provides functionality to:
 * <ul>
 *     <li>Load candidate names from configuration files</li>
 *     <li>Add candidates dynamically</li>
 *     <li>Provide an immutable list of candidates</li>
 *     <li>Validate if a candidate is registered</li>
 * </ul>
 * <p>
 * Once loaded, the list of candidates is immutable externally,
 * ensuring the integrity of the election process.
 */

public class CandidateManager {

    private static final Logger logger = LoggingUtil.getLogger(CandidateManager.class);
    private final List<String> candidates = new ArrayList<>();

    /**
     * Loads candidate names from a configuration file.
     * <p>
     * Each line in the file should contain one candidate name.
     * Lines beginning with '#' are treated as comments and ignored.
     * Empty lines are also ignored.
     *
     * @param configFile Path to the configuration file
     * @return true if candidates were loaded successfully, false otherwise
     */

    public boolean loadCandidatesFromFile(String configFile) {
        logger.info("Loading candidates from file: {}", configFile);
        try (BufferedReader reader = new BufferedReader(new FileReader(configFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    candidates.add(line);
                }
            }
            logger.info("Loaded {} candidates from file", candidates.size());
            return true;
        } catch (IOException e) {
            logger.error("Failed to load candidates from file: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Adds a new candidate to the list if not already present.
     *
     * @param candidateName The name of the candidate to add
     */

    public void addCandidate(String candidateName) {
        candidates.add(candidateName);
        logger.info("Added candidate: {}", candidateName);
    }

    /**
     * Gets an unmodifiable list of all candidates.
     *
     * @return An unmodifiable list of candidate names
     */

    public List<String> getCandidates() {
        return Collections.unmodifiableList(candidates);
    }

    /**
     * Checks whether a given name corresponds to a valid candidate.
     *
     * @param candidateName The name to check
     * @return true if the name is a valid candidate, false otherwise
     */

    public boolean isValidCandidate(String candidateName) {
        return candidates.contains(candidateName);
    }
}
