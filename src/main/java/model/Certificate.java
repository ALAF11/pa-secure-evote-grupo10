package model;

import java.security.cert.X509Certificate;
import java.util.Base64;

//Represents an X.509 digital certificate - Supports PEM read/write

public class Certificate {

    private final X509Certificate certificate;

    public Certificate (X509Certificate certificate){
        this.certificate = certificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String toPEM() throws Exception {
        byte[] encoded = certificate.getEncoded();
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----";
    }

    public static Certificate fromPEM(String pem) throws Exception {
        String base64 = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        byte[] decoded = Base64.getDecoder().decode(base64);
        var factory = java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(decoded));
        return new Certificate(cert);
    }
}
