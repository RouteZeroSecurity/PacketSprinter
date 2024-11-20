# PacketSprinter: Send Requests in Parallel

**Author**: Richard Hyunho Im ([@richeeta](https://github.com/richeeta)), [Route Zero Security](https://routezero.security) 

**Testing & Code Review**: Gabriela Loya (@sh4d0w_m00n), Phil Scott (@MrPeriPeri)

---

## 📖 Summary

**PacketSprinter** is a Burp Suite extension that simplifies and enhances HTTP/2 single-packet attack testing by streamlining the otherwise cumbersome process of duplicating, editing, and sending grouped parallel requests within an intuitive UI that displays a side-by-side comparison of requests and responses. PacketSprinter eliminates the need to switch between multiple Repeater tabs, saving time and reducing the chances of error.

This extension is inspired by the research of [James Kettle](https://portswigger.net/research/the-single-packet-attack-making-remote-race-conditions-local), who introduced the **single-packet attack** as a groundbreaking method to make remote race condition testing as effective as local testing. PacketSprinter makes this technique accessible, efficient, and seamless for penetration testers and bug bounty hunters.

🔗 Learn more about Burp Suite's native "Send grouped HTTP requests" feature in [PortSwigger’s documentation](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group).

---

## 🌟 Features

- **HTTP/2 Single-Packet Attack Support**: Implements advanced race condition testing using the single-packet attack technique.
- **Unified UI**: Manage all requests and responses within the same tab—no need to switch between multiple Repeater tabs.
- **Request Duplication Made Easy**: Duplicate requests in bulk with a customizable count and seamlessly edit them in the same interface.
- **Side-by-Side Response Comparison**: View responses side-by-side with built-in highlighting for differences in status codes, headers, and body content.
- **Streamlined Workflow**: Automates the `Send requests in parallel` process, reducing manual effort and improving accuracy.
- **Customizable Controls**: Adjust the number of duplicate requests.

---

## 🛠️ Limitations 

1. **HTTP/1.1 Support**:  
   - Currently, **HTTP/1.1 last-byte synchronization** is **not supported**. Support for this feature is actively being developed and will be included in the next release.  
   - Learn more about HTTP/1.1 last-byte synchronization in the [Burp Suite documentation](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group).

2. **HTTP/3 Support**:  
   - **Not supported at this time**. While HTTP/3 may eventually be added, there are no plans for implementation in the near future.  

3. **Server Behavior Dependency**:  
   - The effectiveness of race condition testing relies heavily on how the target server processes concurrent requests.

---

## ⚠️ Disclaimer 

PacketSprinter is provided **"as is"** without any warranties or guarantees. Users are solely responsible for ensuring proper authorization before testing web applications. Unauthorized testing may violate applicable laws and could result in legal consequences.

**Risks and Potential Impact**:
- Overwhelming a target server with concurrent requests can lead to service disruption or unintentional denial-of-service (DoS) conditions.
- Misconfigured requests may produce inaccurate results or fail to detect vulnerabilities.

Use responsibly and ensure compliance with applicable laws and ethical guidelines.

---

## 🛠️ Setup Instructions 

### Using the Pre-Built JAR File (Recommended)

1. **Download the JAR**:  
   - Visit the [Releases](https://github.com/richeeta/PacketSprinter/releases) section of this repository.
   - Download the latest `PacketSprinter.jar` file.

2. **Install the Extension**:  
   - Open **Burp Suite**.
   - Navigate to `Extensions > Extensions`.
   - Click `Add` and select the downloaded `PacketSprinter.jar` file.

3. **Verify Installation**:  
   - Confirm "PacketSprinter" appears in the list of installed extensions.
   - Open the `PacketSprinter` tab to start using the tool.

---

### Building from Source

#### Prerequisites

- **Java Development Kit (JDK)**: Version 8 or higher ([download here](https://adoptium.net/)).
- **Gradle**: A build automation tool ([installation guide](https://gradle.org/install/)).
- **Burp Suite API JAR**: Obtain the Montoya API from [PortSwigger](https://portswigger.net/burp/extender/api).

#### Steps to Build

1. **Clone the Repository**:  
   ```bash
   git clone https://github.com/richeeta/PacketSprinter.git
   cd PacketSprinter
   ```
2. **Install Dependencies**:
   * Place the Montoya API JAR in the libs/ directory of the project.
3. **Build the JAR**:
    ```bash
    gradle build
    ```
4. **Locate the Built JAR**:
    * The JAR file will be located in the `build/libs/` directory.
5. **Install the Extension**:
    * Follow the instructions in the previous **Using the Pre-Built JAR File** section.

## 🚀 Usage Instructions 
1. **Load a Base Request**:
    * Right-click on a request in Proxy or Repeater and select `PacketSprinter: Send Requests in Parallel`.
2. **Duplicate Requests**:
    * Specify the number of duplicates and click **Duplicate Request**.
3. **Modify Requests**:
    * Edit any loaded request in UI. 
4. **Send Requests in Parallel**:
    * Click Send All Requests to send the requests simultaneously.
5. **Analyze Responses**:
    * Examine all responses side-by-side in the UI. Differences are automatically highlighted for easy analysis.
6. **Clear Requests**:
    * Use the `Clear Requests` button to reset the interface and load new requests.

## 🤝 Contributing 
Contributions are welcome! Here’s how you can help:
* **Report Issues**: Open an issue in the GitHub Issues tab.
* **Submit Pull Requests**: Please fork the repository, create a new branch for your feature/fix, then submit a pull request with a detailed description.
* **Suggest Improvements**: Share your ideas in the Discussions section.

## 📄 License
This project is licensed under the GNU Affero General Public License v3.0.

Enjoy using PacketSprinter! 🚀
