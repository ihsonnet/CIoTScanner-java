import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class SSLCertificateModifier {

    public static void main(String[] args) {
        String keystorePath = "path/to/keystore.jks";
        String keystorePassword = "keystore_password";
        String alias = "certificate_alias";
        String newCommonName = "hello.com";

        try {
            // Load the keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(keystorePath);
            keystore.load(fis, keystorePassword.toCharArray());

            // Get the certificate
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);

            // Modify the common name
            certificate = modifyCommonName(certificate, newCommonName);

            // Update the keystore
            keystore.setCertificateEntry(alias, certificate);

            // Save the modified keystore
            FileOutputStream fos = new FileOutputStream(keystorePath);
            keystore.store(fos, keystorePassword.toCharArray());

            System.out.println("Certificate modified successfully!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate modifyCommonName(X509Certificate certificate, String newCommonName) {
        try {
            // Get the certificate's encoded form
            byte[] encodedCertificate = certificate.getEncoded();

            // Create a new certificate from the encoded form
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(encodedCertificate);
            X509Certificate newCertificate = (X509Certificate) certificateFactory.generateCertificate(bais);

            // Modify the common name in the subject DN
            X500Principal subjectDN = newCertificate.getSubjectX500Principal();
            LdapName ldapName = new LdapName(subjectDN.getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    ldapName.remove(rdn);
                    ldapName.add(new Rdn("CN", newCommonName));
                    break;
                }
            }

            // Update the subject DN in the new certificate
            byte[] encodedNewCertificate = newCertificate.getEncoded();
            CertificateFactory newCertificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream newBais = new ByteArrayInputStream(encodedNewCertificate);
            X509Certificate modifiedCertificate = (X509Certificate) newCertificateFactory.generateCertificate(newBais);

            return modifiedCertificate;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
