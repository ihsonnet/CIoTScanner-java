/**
 * Initiates the Man-in-the-middle server and DNS in two seperate threads.
 * Takes in 1-3 arguments, verbose option, specify app flag and Certificate-Host map file
 *
 * Chris McMahon-Stone (c.mcmahon-stone@cs.bham.ac.uk)
 */

import java.io.*;
import java.util.*;
import java.util.stream.*;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;

import java.text.*;
import java.time.LocalDateTime;

public class Launcher {

    @Parameter(names={"--verbosity", "-v"}, description = "Verbosity of output", required = false)
        int verbose = 2;
    @Parameter(names={"--manual", "-m"}, description = "Hostname to redirect traffic too", required = false)
        String redirectHost;
    @Parameter(names={"--log", "-l"}, description = "Optionally specify logging file", required = false)
        String logFile;
    @Parameter(names={"-dns"}, description = "DNS only", required = false)
        boolean dnsOnly = false;
    @Parameter(names={"-h", "--help"}, description = "Show help", required = false)
        boolean help = false;
    @Parameter(names={"-p", "--passthrough"}, description = "No redirection, just proxy traffic", required = false)
        boolean passthrough = false;
    @Parameter(names={"--whitelist", "-w"}, description = "New line delimited file of domains to spoof to our TLS proxy.", required = false)
        String whiteListFile;
    @Parameter(names={"--config", "-c"}, description = "Config file containing required DNS IP and Censys account credentials", required = true)
        String configFile;

    public static void main(String[] args) throws Exception {

        Launcher main = new Launcher();
        JCommander jc = JCommander.newBuilder().addObject(main).build();
        jc.setProgramName(main.getClass().getName());
        try{
            jc.parse(args);
        } catch(ParameterException e) {
            if(main.help) {
                printIntro();
                jc.usage();
                return;
            } else {
                System.out.println("ERROR: " +e.getMessage());
                jc.usage();
                return;
            }
        }

        if(main.help) {
            printIntro();
            jc.usage();
            return;
        }
	
        Config config = null;
        try {
            config = new Config(main.configFile, main.whiteListFile);
        } catch (FileNotFoundException e) {
            System.out.println("ERROR: " + e.getMessage());
            jc.usage();
            return;
        }

        if(main.logFile == null) {
            main.logFile = "log-" + LocalDateTime.now();
            System.out.println("Writing log to: " + main.logFile);
        }
        PrintWriter logOut = new PrintWriter(new BufferedWriter(new FileWriter(main.logFile, true)));
        FakeDNS dns;
        if(main.dnsOnly) {
            dns = new FakeDNS(null, main.verbose, logOut, null, true, false, config);
            new Thread(dns).start();
            return;
        } else {
            MITM mitm;
            if(main.redirectHost == null) {
                mitm = new MITM(main.verbose, logOut, false, main.passthrough);
                dns = new FakeDNS(mitm, main.verbose, logOut, null, false, main.passthrough, config);
            } else {
                mitm = new MITM(main.verbose, logOut, true, main.passthrough);
                dns = new FakeDNS(mitm, main.verbose, logOut, main.redirectHost, false, main.passthrough, config);
            }
            Scanner scan = new Scanner(System.in);
            Thread dnsThread = new Thread(dns);
            Thread mitmThread = new Thread(mitm);

            dnsThread.start();
            mitmThread.start();

            //Ensure log is written to disk when program is closed
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    logOut.flush();
                    logOut.close();
                }
            });
        }
    }

    private static void printIntro() {
    
        String message = "-------------------------------------------------------------------------------\n" +
                         "-------------------------------------------------------------------------------\n" +
           " $$$$$$\\  $$$$$$\\       $$$$$$$$\\  $$$$$$\\                                                             \n" +
                "$$  __$$\\ \\_$$  _|      \\__$$  __|$$  __$$\\                                                            \n" +
                "$$ /  \\__|  $$ |  $$$$$$\\  $$ |   $$ /  \\__| $$$$$$$\\ $$$$$$\\  $$$$$$$\\  $$$$$$$\\   $$$$$$\\   $$$$$$\\  \n" +
                "$$ |        $$ | $$  __$$\\ $$ |   \\$$$$$$\\  $$  _____|\\____$$\\ $$  __$$\\ $$  __$$\\ $$  __$$\\ $$  __$$\\ \n" +
                "$$ |        $$ | $$ /  $$ |$$ |    \\____$$\\ $$ /      $$$$$$$ |$$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \\__|\n" +
                "$$ |  $$\\   $$ | $$ |  $$ |$$ |   $$\\   $$ |$$ |     $$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      \n" +
                "\\$$$$$$  |$$$$$$\\\\$$$$$$  |$$ |   \\$$$$$$  |\\$$$$$$$\\\\$$$$$$$ |$$ |  $$ |$$ |  $$ |\\$$$$$$$\\ $$ |      \n" +
                " \\______/ \\______|\\______/ \\__|    \\______/  \\_______|\\_______|\\__|  \\__|\\__|  \\__| \\_______|\\__|" +
                         "-------------------------------------------------------------------------------\n" +
                         "-------------------------------------------------------------------------------\n\n" +
                         "-------------------------------------------------------------------------------\n" +
                         " Developed by: Injamamul Haque Sonet\n" +
                         "-------------------------------------------------------------------------------\n\n" +
                         " Tool to enable detection of applications that pin to non-leaf TLS certificates in CIoT devices\n " +
                         "and fail to carry out hostname verification. \n\n" +
                         " CIoTScanner analyses the certificate chain of the requested domains and redirects \n" +
                         " TLS traffic to other sites, which it finds on Censys.io, that use the same \n" +
                         " certificate chain. The handshake is then proxied to determine if encrypted \n" +
                         " application data is sent by the app to the domain that the app is not expecting.\n\n\n" +
                         " The target device is required to use Spinner's IP for DNS requests. An \n" +
                         " account on Censys is also required, credentials should be specified in the \n" +
                         " config file.\n\n";


        System.out.println(message);
    }

}

