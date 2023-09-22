# Scanning-Test-Project

- Scan given IP's provided by user to determine the engine a frontend is using and the version of that engine.

## Development Notes:

- [Python environment setup](docs/README.md)

### Run Application

- Within the root of the project folder ensure you're in a virtual environment. See Dev Notes, if you have issues.
- To run the application, use python3 or python (whatever command works with your system), followed by: -m src.controller.ip_scanner
- Example: python3 -m src.controller.ip_scanner

**Potential Issues**

- If you receieve issues running the program related to NMAP, ensure your PATH is set correctly in your environment variables.

- If path is set correctly and still having issues, you will need to install nmap than map your PATH in your environment variables to the NMAP directory.

