package model;

import org.slf4j.Logger;
import util.LoggingUtil;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CandidateManager {

    private static final Logger logger = LoggingUtil.getLogger(CandidateManager.class);
    private final List<String> candidates = new ArrayList<>();

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

    public void addCandidate(String candidateName) {
        candidates.add(candidateName);
        logger.info("Added candidate: {}", candidateName);
    }

    public List<String> getCandidates() {
        return Collections.unmodifiableList(candidates);
    }

    public boolean isValidCandidate(String candidateName) {
        return candidates.contains(candidateName);
    }
}
