# Splunk SPL Command Generator

A professional web-based tool for generating Splunk Search Processing Language (SPL) commands with predefined templates and customizable filters, specifically designed for Splunk Cloud environments.

## Features

- **38 Predefined Templates**: Comprehensive collection of DFIR, security, network, and system monitoring templates
- **Real-time SPL Generation**: Instant command generation with syntax validation
- **Customizable Filters**: Add, remove, and reorder filters with drag-and-drop functionality
- **Multiple Command Types**: Support for `search`, `tstats`, `stats`, and other SPL commands
- **Time Range Management**: Predefined time ranges with custom input options
- **Dark/Light Theme**: Toggle between themes for better user experience
- **Command History**: Save and load previously generated commands
- **Auto-save**: Automatic saving of current configuration
- **Copy to Clipboard**: One-click copying of generated commands
- **Professional UI**: Modern, responsive interface built with Bootstrap 5

## Screenshot

![Splunk SPL Command Generator Interface](screenshot.png)

*Screenshot showing the main interface with template selection, filter configuration, and generated SPL command display.*

## Installation

### Quick Start
1. Download all project files
2. Run `SplunkGenerator.bat` to launch the application
3. The tool will open in your default web browser

### Alternative Launch Methods
- Double-click `index.html` directly
- Use `create-shortcut.bat` to create a desktop shortcut

## Usage

### Using Templates
1. Select a template from the categorized sections (DFIR & Security, Network Security, etc.)
2. The form will be populated with predefined values
3. Customize fields, filters, and time ranges as needed
4. Click "Generate SPL Command" to create the command
5. Copy the generated command to use in Splunk Cloud

### Creating Custom Commands
1. Choose the command type (search, tstats, stats, etc.)
2. Select appropriate index and sourcetype
3. Enter search string or leave blank for tstats commands
4. Add filters using the "Add Filter" button
5. Set time range or use custom time input
6. Generate and copy the command

### Advanced Features
- **Drag and Drop**: Reorder filter rows by dragging
- **Auto-completion**: Get suggestions for common SPL fields
- **Real-time Validation**: Immediate feedback on command syntax
- **Configuration Management**: Save and load custom configurations

## Template Categories

### DFIR & Security (25 templates)
- Malware Detection
- Suspicious Logins
- Failed Authentication
- Privilege Escalation
- Data Exfiltration
- Command Execution
- Lateral Movement
- Persistence Mechanisms
- Ransomware Activity
- Suspicious Processes
- File System Changes
- Registry Changes
- Scheduled Tasks
- Service Changes
- User Account Changes
- Group Membership Changes
- Network Shares
- Remote Desktop Activity
- PowerShell Activity
- WMI Activity
- Certificate Changes
- Antivirus Events
- Firewall Rule Changes
- Email Security
- System Integrity

### Network Security (4 templates)
- Network Connections
- DNS Queries
- Web Proxy Analysis
- Network Protocols

### System Monitoring (4 templates)
- Backup Monitoring
- Patch Management
- Vulnerability Scan
- Incident Timeline

### Additional Security (5 templates)
- Data Loss Prevention
- Endpoint Detection
- Web Security
- User Activity
- Compliance & Audit

## File Structure

```
Splunk-generator/
├── index.html              # Main application interface
├── script.js               # Core JavaScript functionality
├── styles.css              # Custom styling and themes
├── SplunkGenerator.bat     # Main launcher script
├── create-shortcut.bat     # Desktop shortcut creator
├── README.md               # This documentation
├── TEMPLATES_GUIDE.md      # Detailed template documentation
├── PROJECT_SUMMARY.md      # Project overview and features
└── CLEANUP_REPORT.md       # Development cleanup documentation
```

## Technical Details

### SPL Compatibility
All generated commands are tested and compatible with Splunk Cloud:
- Uses standard SPL operators (`=`, `!=`, `>`, `>=`, `<`, `<=`, `IN`, `NOT IN`, `MATCHES`, `NOT MATCHES`)
- Proper field naming conventions
- Correct `tstats` command syntax
- Validated time range formats

### Browser Compatibility
- Chrome (recommended)
- Firefox
- Edge
- Safari

### Dependencies
- Bootstrap 5.3.0
- Font Awesome 6.4.0
- Modern browser with ES6+ support

## Development

### Local Development
1. Clone the repository
2. Open `index.html` in a web browser
3. Use browser developer tools for debugging

### Customization
- Add new templates in `script.js` under `initializeTemplates()`
- Modify styling in `styles.css`
- Update UI elements in `index.html`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly with Splunk Cloud
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Support

For issues, questions, or contributions, please use the GitHub repository's issue tracker.

## Version History

- **v1.0**: Initial release with 38 templates
- **v1.1**: Added dark mode, history, and advanced features
- **v1.2**: Improved SPL compatibility and UI enhancements
