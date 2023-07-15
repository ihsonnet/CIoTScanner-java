# CIoTScanner: Automatic Detection of SSL/TLS Certificate Pinning without Hostname verification in COnsumer IoT Devices

CIoTscanner: Automatic Detection of SSL/TLS Certificate Pinning Without Hostname Verification in Consumer IoT Devices, an automated detection tool developed to tackle this issue and enhance the security of CIoT devices. By employing a Raspberry Pi 4 as a gateway. The CIoTscanner intercepts SSL certificates exchanged between CIoT devices and servers. Allowing for the detection of instances where SSL/TLS certificate pinning vulnerabilities exist. The tool not only reduces costs associated with purchasing certificates but also lessens the burden of manual testing, making it highly valuable for developers, testers, and manufacturers alike. Moreover, CIoTscanners' automated detection capabilities enhance the overall security of CIoT devices by mitigating the risks associated with SSL/TLS certificate pinning and contributing to the advancement of secure CIoT ecosystems.


**To compile:**

On Linux: ```javac -cp .:libs/* *.java```

On Windows: ```javac -cp ".;libs/*" *.java```

**Set up:**

Either:
* Set DNS of mobile device to use IP of machine running Spinner e.g. In android: WiFi -> Modify Network -> Advanced -> IP Settings, Static -> DNS

or

* Run Spinner on machine with access point e.g. hostapd. Connect testing device to AP running Spinner. 

**To run:**

On Linux: ```sudo java -cp .:libs/* Launcher --help```

On Windows: ```java -cp ".;libs/*" Launcher --help```


(Note: root is required as a TLS and DNS server are ran on privileged ports)

The program requires a config file which contains the IP address of the DNS server on your network, and the credentials to use with Censys.io. You will need to sign up for an account here https://censys.io/register. 


**Example usage**

Run the tool with config details specified in the file ```config``` and ignore connections to domains listed in ```whitelist```

```sudo java -cp .:libs/* Launcher -c config -w whitelist```

Run the tool without using Censys by manually specifying a redirect domain. 

```sudo java -cp .:libs/* Launcher -m google.com```


**Disclaimer**: This tool is intended for research use, and is currently undergoing further development. We welcome any feedback which can be provided by raising issues or pull requests.


