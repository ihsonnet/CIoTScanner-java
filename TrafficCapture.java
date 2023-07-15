import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class TrafficCapture {

    public static void main(String[] args) {
        String targetWebsite = "amarnatok.com";
        int numPackets = 10; // Number of packets to capture

        try {
            // Construct the tshark command
            String[] tsharkCommand = {
                    "tshark",
                    "-i", "eth0", // Replace with the appropriate network interface name
                    "-f", "host " + targetWebsite,
                    "-c", String.valueOf(numPackets),
                    "-T", "fields",
                    "-e", "ssl.handshake.certificate"
            };

            // Start the tshark process
            ProcessBuilder processBuilder = new ProcessBuilder(tsharkCommand);
            Process process = processBuilder.start();

            // Read the captured packets from the process output
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                // Process the captured packet
                if (line.startsWith("0x")) {
                    String base64Certificate = line.substring(2);
                    byte[] certificateBytes = Base64.getDecoder().decode(base64Certificate);

                    // Convert to X509Certificate
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));

                    // Print certificate details in PEM format
                    System.out.println("-----BEGIN CERTIFICATE-----");
                    System.out.println(Base64.getMimeEncoder().encodeToString(certificate.getEncoded()));
                    System.out.println("-----END CERTIFICATE-----");
                }
            }

            // Wait for the process to complete
            process.waitFor();

        } catch (IOException | InterruptedException | CertificateException e) {
            e.printStackTrace();
        }
    }
}
