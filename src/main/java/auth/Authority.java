package auth;

import crypto.CryptoUtils;
import crypto.KeyManager;
import model.Certificate;
import model.VoterCertificateRequest;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class Authority {

    private static final String PRIVATE_KEY_PATH = "keys/authority_private.key";
    private static final String PUBLIC_KEY_PATH = "keys/authority_public.key";
    private static final String CERT_DIR = "certs/";
    private final String VALID_CERTS_FILE = "certs/valid_certs.list";

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private final Map<String, Certificate> validCertificates = new HashMap<>();

    public Authority() throws Exception {
        initializeKeys();
        loadValidCertificates();
    }

    private void initializeKeys() throws Exception {
        if (!KeyManager.keyPairExists(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)) {
            KeyManager.generateAndStoreKeyPair(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH);
        }
        this.privateKey = KeyManager.loadPrivateKey(PRIVATE_KEY_PATH);
        this.publicKey = KeyManager.loadPublicKey(PUBLIC_KEY_PATH);
    }

    private void loadValidCertificates() throws IOException {
        File file = new File(VALID_CERTS_FILE);
        if (!file.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                File certFile = new File(CERT_DIR + line + ".pem");
                if(certFile.exists()) {
                    try {
                        Certificate cert = Certificate.fromPEM(Files.readString(certFile.toPath()));
                        validCertificates.put(line, cert);
                    } catch (Exception e) {
                        System.err.println("Erro ao carregar certificado " + line);
                    }
                }
            }
        }
    }

    private void saveCertificateToFile(String certId, Certificate certificate) throws Exception {
        File dir = new File(CERT_DIR);
        if (!dir.exists()) dir.mkdirs();
        String pem = certificate.toPEM();
        Files.write(Path.of(CERT_DIR + certId + ".pem"), pem.getBytes());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(VALID_CERTS_FILE, true))) {
            writer.write(certId);
            writer.newLine();
        }
    }

    public Certificate signCertificate(VoterCertificateRequest request) throws Exception {
        String certId = request.getId();
        byte[] csrData = request.toBytes();
        byte[] signature = CryptoUtils.sign(csrData, privateKey);
        Certificate signedCert = request.toCertificate(signature);
        saveCertificateToFile(certId, signedCert);
        validCertificates.put(certId, signedCert);
        return signedCert;
    }

    public boolean isCerticateValid(String certID) {
        return validCertificates.containsKey(certID);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
