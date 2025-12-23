# Dynamic Kali Linux Everything MCP Server

A Model Context Protocol (MCP) server that provides dynamic access to ALL security tools in Kali Linux Everything edition, creating fresh containers for each command execution.

## Purpose

This MCP server provides access to the complete Kali Linux security toolkit through dynamically generated MCP tools. Each command runs in a fresh, isolated container for maximum security and isolation.

## Features

### Dynamic Tool Discovery
- **Automatic Discovery:** Scans Kali Linux Everything image for all available security tools
- **Category Organization:** Groups tools by functionality (Web App Testing, Password Attacks, etc.)
- **Fresh Containers:** Each command runs in a new, clean container
- **Zero Persistence:** No data persists between command executions

### Tool Categories Include
- **Information Gathering** - nmap, masscan, dnsenum, whois, etc.
- **Vulnerability Analysis** - nikto, sqlmap, wpscan, gobuster, etc.
- **Database Assessment** - SQL injection and database testing tools
- **Password Attacks** - john, hashcat, hydra, medusa, etc.
- **Wireless Attacks** - aircrack-ng, wireshark, bettercap, etc.
- **Reverse Engineering** - radare2, ghidra, binwalk, etc.
- **Exploitation Tools** - metasploit, msfconsole, beef, etc.
- **Sniffing & Spoofing** - wireshark, mitmproxy, ettercap, etc.
- **Forensics** - volatility, autopsy, sleuthkit, etc.
- **Social Engineering** - setoolkit, gophish, theharvester, etc.

### Static Management Tools
- **`list_security_tools`** - Browse all available tools by category
- **`get_tool_info`** - Get detailed usage information for any tool
- **`search_tools`** - Find tools by keyword search
- **`container_status`** - Check Docker and container status

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Access to pull Kali Linux Everything image (~10GB)
- Sufficient disk space for large Docker images

## Installation

See step-by-step instructions provided with files.

## Usage Examples

In Claude Desktop, you can ask:

### Tool Discovery
- "List all web application testing tools"
- "Search for password cracking tools"
- "Show me information gathering tools"
- "Get help for nmap"
- "Search for tools containing 'sql'"

### Direct Tool Execution
- "nmap -sS -p 1-1000 example.com"
- "nikto -h http://target.com"
- "sqlmap -u 'http://test.com/page.php?id=1' --dbs"
- "wpscan --url http://blog.com --enumerate p"
- "searchsploit apache 2.4"
- "hydra -l admin -P rockyou.txt ssh://192.168.1.1"

### Management Commands
- "Check container status"
- "List all available tools"
- "Search for wireless tools"

## Architecture

```
Claude Desktop → MCP Gateway → Dynamic Kali MCP Server → Fresh Containers (per command)
                                              ↓
                                    Kali Linux Everything Image (All Tools)
```

## Security Features

### Isolation
- Each command runs in completely fresh container
- No data persistence between executions
- Automatic container cleanup
- Non-root user execution

### Safety
- Input sanitization prevents command injection
- Dangerous command pattern detection
- Timeouts prevent runaway processes
- Educational use warnings

### Resource Management
- Automatic container lifecycle management
- Configurable timeouts per tool category
- Memory and CPU isolation
- Container name tracking and cleanup

## Development

### Local Testing

```bash
# Set environment variables
export KALI_TARGET_TIMEOUT=120
export KALI_CONTAINER_PREFIX=kali-test
export KALI_IMAGE=kalilinux/kali-rolling-everything

# Run directly
python3 kali_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python3 kali_server.py
```

### Tool Categories
The server automatically discovers and categorizes tools based on common security tool groupings. Tools are dynamically registered as MCP functions.

### Adding Custom Categories
Modify the `security_tools` dictionary in `kali_server.py` to add new categories or tool groupings.

## Troubleshooting

### First Run Setup
- First execution downloads Kali Linux Everything image (~10GB)
- Initial tool discovery takes 2-3 minutes
- Subsequent runs use cached information

### Tool Not Found
- Verify image pulled successfully: `docker images kalilinux/kali-rolling-everything`
- Check tool discovery logs for errors
- Try `list_security_tools` to see available tools

### Container Errors
- Check Docker daemon is running
- Verify sufficient disk space
- Check network connectivity for image pulls
- Review container logs: `docker logs <container-name>`

### Performance
- Kali Everything image requires significant resources
- Consider specific Kali images for better performance
- Increase timeouts for intensive operations

## Configuration Options

Environment Variables:
- **KALI_TARGET_TIMEOUT**: Command timeout in seconds (default: 120)
- **KALI_CONTAINER_PREFIX**: Container name prefix (default: kali-mcp)
- **KALI_IMAGE**: Docker image to use (default: kalilinux/kali-rolling-everything)

## Legal Notice

⚠️ **CRITICAL:** This server provides access to professional security testing tools.

- **ONLY** use on systems you own or have explicit written permission to test
- **NEVER** use on systems without authorization
- **RESPONSIBLE** usage is required at all times
- **EDUCATIONAL** purposes only
- **LEGAL** compliance is your responsibility

Unauthorized security testing may result in:
- Criminal charges
- Civil liability
- Network termination
- Legal prosecution

## License

MIT License

## Resource Requirements

- **Minimum:** 8GB RAM, 50GB free disk space
- **Recommended:** 16GB RAM, 100GB free disk space
- **Network:** Broadband for initial image download