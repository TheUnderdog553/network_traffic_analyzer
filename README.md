# Network Traffic Analyzer

A Python-based network traffic analysis tool that can analyze CSV files exported from Wireshark or other network packet capture tools.

## Features

- **Data Analysis**: View network traffic data, source/destination counts, and protocol statistics
- **Graph Visualization**: Create network graphs and protocol-based bar charts
- **Suspect Tracing**: Trace specific IP addresses in the network traffic
- **Geolocation**: Find the country location of public IP addresses (requires GeoLite2 database)

## Installation

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Download GeoLite2 Database (Optional):**
   - For geolocation features, download the GeoLite2-Country.mmdb file
   - Place it in the same directory as the script
   - You can download it from MaxMind (free registration required)

## Usage

1. **Run the program:**
   ```bash
   python NetworyAnalyzer.py
   ```

2. **Load your CSV file:**
   - The program expects CSV files exported from Wireshark
   - Required columns: "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"
   - Enter the full path to your CSV file when prompted

3. **Navigate the menu:**
   - **Show Data**: View traffic statistics and protocol information
   - **Build Graphs**: Create network visualizations and charts
   - **Trace Suspected Address**: Analyze specific IP addresses
   - **Geolocation**: Find country information for public IPs

## CSV Format

The program expects CSV files with the following columns:
- No.: Packet number
- Time: Timestamp
- Source: Source IP address
- Destination: Destination IP address
- Protocol: Network protocol (TCP, UDP, DNS, etc.)
- Length: Packet length
- Info: Additional packet information

## Cross-Platform Support

The program now works on:
- Windows
- Linux
- macOS

## Dependencies

- pandas: Data manipulation and analysis
- matplotlib: Plotting and visualization
- networkx: Network graph creation and analysis
- geoip2: IP geolocation (optional)
- pyfiglet: ASCII art banner
- pyvis: Interactive network visualization

## Troubleshooting

1. **Missing dependencies**: Run `pip install -r requirements.txt`
2. **CSV format errors**: Ensure your CSV has the required columns
3. **Geolocation not working**: Download and place the GeoLite2-Country.mmdb file
4. **Graph display issues**: Ensure you have a display environment (for matplotlib)

## Author

Created by Priyanshu Singh
- GitHub: https://github.com/TheUnderdog553
- LinkedIn: www.linkedin.com/in/priyanshu-singh-a50a22265 