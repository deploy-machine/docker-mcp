#!/usr/bin/env python3
"""
Kali Linux Security MCP Server - UNIFIED COMMAND RUNNER VERSION
Based on unified command runner approach but specialized for Kali security tools.
"""
import os
import sys
import logging
import subprocess
import json
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("kali-security-server")

# Initialize MCP server
mcp = FastMCP("kali-security")

# Configuration
SECURITY_TIMEOUT = int(os.environ.get("KALI_TARGET_TIMEOUT", "120"))
CONTAINER_PREFIX = os.environ.get("KALI_CONTAINER_PREFIX", "kali-security")
KALI_BASE_IMAGE = os.environ.get("KALI_BASE_IMAGE", "kali-security-mcp-server:latest")
MAX_WORKERS = int(os.environ.get("KALI_DISCOVERY_WORKERS", "10"))

# Global tool cache
AVAILABLE_TOOLS = {}
TOOL_CATEGORIES = {}
DISCOVERY_INFO = {}
LAST_DISCOVERY_TIME = 0
DISCOVERY_CACHE_TTL = 3600
TOOL_CACHE_FILE = os.environ.get("KALI_CACHE_FILE", "/mcp/kali-tools-cache.json")

# Thread-safe lock
discovery_lock = Lock()

# Kali security command definitions
COMMAND_DEFINITIONS = {
    # Information Gathering
    "nmap": {
        "description": "Network discovery and security auditing tool",
        "category": "Information Gathering",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Nmap arguments (e.g., '-sS -p 1-1000 target.com')"}
        }
    },
    "whois": {
        "description": "Domain information lookup",
        "category": "Information Gathering", 
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Whois arguments"}
        }
    },
    "ping": {
        "description": "Network ping tool",
        "category": "Information Gathering",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Ping arguments"}
        }
    },
    
    # Web Application Analysis
    "nikto": {
        "description": "Web server scanner",
        "category": "Web Application Analysis",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Nikto arguments"}
        }
    },
    "sqlmap": {
        "description": "SQL injection and database takeover tool",
        "category": "Web Application Analysis",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "SQLMap arguments"}
        }
    },
    "dirb": {
        "description": "Web content scanner",
        "category": "Web Application Analysis",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Dirb arguments"}
        }
    },
    "gobuster": {
        "description": "Directory/file, DNS and VHost busting tool",
        "category": "Web Application Analysis", 
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Gobuster arguments"}
        }
    },
    
    # Password Attacks
    "john": {
        "description": "John the Ripper password cracker",
        "category": "Password Attacks",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "John the Ripper arguments"}
        }
    },
    "hashcat": {
        "description": "Advanced password recovery tool",
        "category": "Password Attacks",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Hashcat arguments"}
        }
    },
    "hydra": {
        "description": "Online password cracking tool",
        "category": "Password Attacks",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Hydra arguments"}
        }
    },
    
    # Vulnerability Analysis
    "lynis": {
        "description": "Security auditing tool for Unix/Linux systems",
        "category": "Vulnerability Analysis",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Lynis arguments"}
        }
    },
    
    # Exploitation Tools
    "msfconsole": {
        "description": "Metasploit Framework console",
        "category": "Exploitation Tools",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Metasploit console arguments"}
        }
    },
    
    # Wireless Attacks
    "aircrack-ng": {
        "description": "WiFi security auditing tools suite",
        "category": "Wireless Attacks",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Aircrack-ng arguments"}
        }
    },
    
    # Sniffing & Spoofing
    "wireshark": {
        "description": "Network protocol analyzer",
        "category": "Sniffing & Spoofing",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Wireshark arguments"}
        }
    },
    "tcpdump": {
        "description": "Network capture and analysis tool",
        "category": "Sniffing & Spoofing",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Tcpdump arguments"}
        }
    },
    
    # Forensics
    "volatility": {
        "description": "Memory forensics framework",
        "category": "Forensics",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Volatility arguments"}
        }
    },
    "autopsy": {
        "description": "Digital forensics platform",
        "category": "Forensics",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Autopsy arguments"}
        }
    },
    
    # Social Engineering
    "setoolkit": {
        "description": "Social Engineer Toolkit",
        "category": "Social Engineering",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "SET arguments"}
        }
    }
}

def discover_kali_tools_optimized(force_refresh: bool = False) -> dict:
    """Optimized tool discovery with caching"""
    global LAST_DISCOVERY_TIME, AVAILABLE_TOOLS, TOOL_CATEGORIES, DISCOVERY_INFO
    
    current_time = time.time()
    
    # Check cache first
    if not force_refresh:
        if (current_time - LAST_DISCOVERY_TIME) < DISCOVERY_CACHE_TTL and AVAILABLE_TOOLS:
            logger.info("📦 Using in-memory cache")
            return {
                "tools": AVAILABLE_TOOLS,
                "categories": TOOL_CATEGORIES,
                "discovery_info": DISCOVERY_INFO
            }
    
    logger.info("🔍 Starting tool discovery...")
    start_time = time.time()
    
    try:
        # Quick filesystem scan
        get_bins_cmd = "find /usr/bin /usr/sbin /usr/local/bin -type f -executable 2>/dev/null | sort"
        result = subprocess.run(get_bins_cmd, shell=True, capture_output=True, text=True, timeout=60)
        binaries = [b for b in result.stdout.strip().split('\n') if b.strip()]
        
        # Categorize tools
        category_keywords = {
            "Information Gathering": ["nmap", "scan", "enum", "recon", "discover", "ping", "traceroute", "dig", "dns", "whois", "host", "net", "arp", "mass", "amass", "sublist", "fierce", "dnsenum", "dnsrecon"],
            "Web Application Analysis": ["nikto", "sqlmap", "wpscan", "dirb", "gobuster", "wfuzz", "ffuf", "burp", "zap", "skipfish", "arachni", "whatweb", "joomscan", "droopescan", "cmseek", "aquatone", "subfinder"],
            "Vulnerability Analysis": ["openvas", "nessus", "nexpose", "vuln", "audit", "check", "test", "lynis", "chkrootkit", "rkhunter"],
            "Database Assessment": ["sql", "database", "mysql", "postgres", "oracle", "mdb", "db", "sqlninja", "sqlmate", "bbsql"],
            "Password Attacks": ["john", "hashcat", "hydra", "medusa", "ncrack", "patator", "crowbar", "cewl", "crunch", "mask", "wordlist", "rainbow", "ophcrack"],
            "Wireless Attacks": ["aircrack", "wifi", "bluetooth", "kismet", "wifite", "fern", "bettercap", "airodump", "aireplay", "airmon", "bluesnarfer", "cowpatty"],
            "Reverse Engineering": ["radare", "ghidra", "gdb", "objdump", "strace", "ltrace", "readelf", "strings", "hexdump", "binwalk", "yara", "volatility", "foremost", "disasm", "edb-debugger"],
            "Exploitation Tools": ["metasploit", "msf", "exploit", "payload", "shell", "bind", "reverse", "beef", "setoolkit", "empire", "cobaltstrike", "powercat", "netcat", "socat", "pwncat", "armitage"],
            "Sniffing & Spoofing": ["wireshark", "tcpdump", "tshark", "dsniff", "arpspoof", "dnsspoof", "ettercap", "mitm", "sslstrip", "macof", "ngrep"],
            "Forensics": ["autopsy", "sleuthkit", "volatility", "dd", "guymager", "photorec", "testdisk", "scalpel", "extundelete", "exiftool", "log2timeline", "plaso", "image", "recover", "bulk-extractor"],
            "Social Engineering": ["setoolkit", "gophish", "king", "evilginx", "modlishka", "creepy", "maltego", "recon-ng", "theharvester", "shodan", "smtp-user-enum"],
        }
        
        tools = {}
        categories = {cat: [] for cat in category_keywords.keys()}
        
        for binary in binaries:
            tool_name = binary.split('/')[-1]
            for category, keywords in category_keywords.items():
                if any(keyword in tool_name.lower() for keyword in keywords):
                    tools[tool_name] = category
                    categories[category].append(tool_name)
                    break
        
        # Remove empty categories
        categories = {k: v for k, v in categories.items() if v}
        
        elapsed = time.time() - start_time
        logger.info(f"✅ Discovery completed in {elapsed:.2f}s - {len(tools)} tools in {len(categories)} categories")
        
        discovery_info = {
            "binaries_found": len(binaries),
            "tools_categorized": len(tools),
            "categories": len(categories),
            "discovery_time_seconds": elapsed
        }
        
        # Update global cache
        with discovery_lock:
            AVAILABLE_TOOLS = tools
            TOOL_CATEGORIES = categories
            DISCOVERY_INFO = discovery_info
            LAST_DISCOVERY_TIME = current_time
        
        return {
            "tools": tools,
            "categories": categories,
            "discovery_info": discovery_info
        }
        
    except Exception as e:
        logger.error(f"❌ Error discovering tools: {e}")
        return {"tools": {}, "categories": {}, "discovery_info": {}}

def initialize_tools():
    """Initialize available tools on startup"""
    global AVAILABLE_TOOLS, TOOL_CATEGORIES, DISCOVERY_INFO
    discovery_result = discover_kali_tools_optimized()
    AVAILABLE_TOOLS = discovery_result["tools"]
    TOOL_CATEGORIES = discovery_result["categories"]
    DISCOVERY_INFO = discovery_result.get("discovery_info", {})

def sanitize_input(input_str: str) -> str:
    """Sanitize input to prevent command injection"""
    if not input_str or not input_str.strip():
        return ""
    cleaned = re.sub(r'[;&|`$()<>]', '', input_str.strip())
    return re.sub(r'[^a-zA-Z0-9._\-/@:]', '', cleaned)

def is_safe_command(command: str) -> bool:
    """Check if command is safe to execute"""
    dangerous_patterns = [
        r'rm\s+/', r'chmod\s+777', r'sudo\s+su', r'passwd',
        r'useradd', r'userdel', r'>\s*/dev/', r'format', r'fdisk', r'mkfs'
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return False
    return True

def setup_security_container(container_name: str) -> str:
    """Setup security container"""
    try:
        logger.info(f"Starting security container: {container_name}")
        start_cmd = f"docker run -d --name {container_name} --rm --cap-add=NET_RAW --cap-add=NET_ADMIN {KALI_BASE_IMAGE} tail -f /dev/null"
        result = subprocess.run(start_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return f"❌ Error starting container: {result.stderr}"
        
        time.sleep(2)
        logger.info(f"Container {container_name} ready")
        return ""
        
    except Exception as e:
        return f"❌ Error setting up container: {str(e)}"

def run_security_command_in_container(command_name: str, args: str, timeout: int = 120) -> str:
    """Run security command in container"""
    container_name = f"{CONTAINER_PREFIX}-{command_name}-{os.getpid()}-{int(time.time())}"
    
    try:
        setup_error = setup_security_container(container_name)
        if setup_error:
            return setup_error
        
        sanitized_args = sanitize_input(args)
        full_command = f"{command_name} {sanitized_args}".strip()
        
        if not is_safe_command(full_command):
            return "❌ Error: Command contains potentially dangerous operations"
        
        exec_cmd = f"docker exec {container_name} {full_command}"
        logger.info(f"Executing: {exec_cmd}")
        
        result = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        output = f"🔧 **Command:** `{full_command}`\n\n"
        
        if result.stdout.strip():
            output += f"**Output:**\n```\n{result.stdout}\n```\n"
        
        if result.stderr.strip():
            output += f"**Errors/Warnings:**\n```\n{result.stderr}\n```\n"
        
        if result.returncode == 0:
            output += "✅ **Success**"
        else:
            output += f"❌ **Failed** (exit code: {result.returncode})"
        
        return output
        
    except subprocess.TimeoutExpired:
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        return f"⏱️ Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Error running security command: {e}")
        return f"❌ Error: {str(e)}"

# === MCP TOOLS ===

@mcp.tool()
async def run_command(command_name: str, args: str = "--help") -> str:
    """
    Execute ANY Kali security tool by name with arguments.
    This dynamically works with ALL 600+ discovered tools, not just predefined ones.
    
    Examples of available tools (from dynamic discovery):
    - Information Gathering: nmap, whois, ping, dig, traceroute, amass, sublist3r
    - Web Application Analysis: nikto, sqlmap, dirb, gobuster, wpscan, ffuf
    - Vulnerability Analysis: lynis, chkrootkit, rkhunter, openvas
    - Password Attacks: john, hashcat, hydra, medusa, patator, cewl
    - Wireless Attacks: aircrack-ng, wifite, bettercap, fern-wifi-cracker
    - Exploitation Tools: msfconsole, metasploit-framework, exploitdb, searchsploit
    - Sniffing & Spoofing: wireshark, tcpdump, tshark, dsniff, ettercap
    - Forensics: volatility, autopsy, sleuthkit, binwalk, foremost, photorec
    - Reverse Engineering: radare2, ghidra, gdb, objdump, strings, hexdump
    - Social Engineering: setoolkit, gophish, theharvester, recon-ng, maltego
    
    Use list_commands() to see ALL available commands and their categories.
    Use get_command_info() to get detailed information about a specific command.
    """
    if not command_name.strip():
        return "❌ Error: command_name is required"
    
    command_name = command_name.strip()
    
    # Ensure tools are discovered
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    # PRIORITY 1: Check discovered tools first (this gives us 600+ tools!)
    if command_name in AVAILABLE_TOOLS:
        category = AVAILABLE_TOOLS[command_name]
        timeout = SECURITY_TIMEOUT
        if category in ["Exploitation Tools", "Password Attacks"]:
            timeout = 300
        elif category in ["Wireless Attacks", "Forensics"]:
            timeout = 180
        
        logger.info(f"✅ Executing discovered tool: {command_name} ({category})")
        return run_security_command_in_container(command_name, args, timeout)
    
    # PRIORITY 2: Fallback to predefined commands for popular tools
    if command_name in COMMAND_DEFINITIONS:
        command_def = COMMAND_DEFINITIONS[command_name]
        category = command_def["category"]
        
        # Adjust timeout based on category
        timeout = SECURITY_TIMEOUT
        if category in ["Exploitation Tools", "Password Attacks"]:
            timeout = 300
        elif category in ["Wireless Attacks", "Forensics"]:
            timeout = 180
        
        logger.info(f"✅ Executing predefined tool: {command_name} ({category})")
        return run_security_command_in_container(command_name, args, timeout)
    
    # Tool not found - provide helpful error
    return f"""❌ Error: Unknown command '{command_name}'. 

Available options:
• Use list_commands() to see ALL {len(AVAILABLE_TOOLS)} discovered tools
• Use search_tools(keyword='your_term') to find specific tools
• Use get_command_info(command_name='tool_name') for details

Example discovered tools: {', '.join(list(AVAILABLE_TOOLS.keys())[:10])}...
"""

@mcp.tool()
async def list_commands(category: str = "") -> str:
    """List ALL available commands from dynamic discovery, optionally filtered by category."""
    # Ensure tools are discovered
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    output = f"🚀 **Kali Linux Security Commands - DYNAMIC DISCOVERY:**\n\n"
    output += f"📊 **Total Discovered Tools: {len(AVAILABLE_TOOLS)}**\n\n"
    
    # Group commands by category from discovered tools
    all_commands = {}
    
    # Add discovered commands (priority!)
    for cmd_name, cat in AVAILABLE_TOOLS.items():
        if cat not in all_commands:
            all_commands[cat] = []
        all_commands[cat].append((cmd_name, {"description": f"Kali security tool", "category": cat}))
    
    # Add predefined commands for popular tools (fallback)
    for cmd_name, cmd_def in COMMAND_DEFINITIONS.items():
        if cmd_name not in AVAILABLE_TOOLS:
            cat = cmd_def["category"]
            if cat not in all_commands:
                all_commands[cat] = []
            all_commands[cat].append((cmd_name, cmd_def))
    
    if category.strip():
        if category in all_commands:
            output += f"**{category} Commands:**\n"
            for cmd_name, cmd_def in all_commands[category]:
                output += f"  - `{cmd_name}`: {cmd_def['description']}\n"
        else:
            available_cats = list(all_commands.keys())
            output += f"❌ Category '{category}' not found. Available: {', '.join(available_cats)}\n"
    else:
        for cat, commands in all_commands.items():
            if commands:
                output += f"**{cat}** ({len(commands)} commands):\n"
                for cmd_name, cmd_def in commands[:15]:  # Show more tools now
                    output += f"  - `{cmd_name}`: {cmd_def['description']}\n"
                if len(commands) > 15:
                    output += f"  - ... and {len(commands) - 15} more commands\n"
                output += "\n"
    
    output += f"\n💡 **Usage:** `run_command(command_name='tool_name', args='your_args')`"
    output += f"\n💡 **Discovery:** Found {len(AVAILABLE_TOOLS)} tools in {len(all_commands)} categories"
    output += "\n💡 **More info:** Use `get_command_info(command_name='tool_name')` for detailed help"
    return output

@mcp.tool()
async def get_command_info(command_name: str = "") -> str:
    """Get detailed information about a specific command."""
    if not command_name.strip():
        return "❌ Error: command_name is required"
    
    command_name = command_name.strip()
    
    # Check known commands first
    if command_name in COMMAND_DEFINITIONS:
        cmd_def = COMMAND_DEFINITIONS[command_name]
        
        output = f"📋 **Command Information: {command_name}**\n\n"
        output += f"**Description:** {cmd_def['description']}\n"
        output += f"**Category:** {cmd_def['category']}\n"
        
        if cmd_def.get("parameters"):
            output += f"\n**Parameters:**\n"
            for param_name, param_info in cmd_def["parameters"].items():
                output += f"  - `{param_name}` ({param_info.get('type', 'string')}): {param_info.get('description', 'No description')}"
                if 'default' in param_info:
                    output += f" [default: {param_info['default']}]"
                output += "\n"
        
        output += f"\n**Example Usage:**\n```\nrun_command(command_name='{command_name}', args='--help')\n```"
        
        return output
    
    # Check discovered tools
    if command_name in AVAILABLE_TOOLS:
        category = AVAILABLE_TOOLS[command_name]
        
        info = f"""📋 **Tool Information: {command_name}**

**Description:** Kali Linux security tool
**Category:** {category}

**Getting Help:**
```
run_command(command_name='{command_name}', args='--help')
```

⚠️ **Legal:** Educational use only."""
        
        return info
    
    return f"❌ Error: Command '{command_name}' not found. Use list_commands() to see available commands."

@mcp.tool()
async def list_security_tools(category: str = "") -> str:
    """List all discovered security tools, optionally filtered by category."""
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    if not AVAILABLE_TOOLS:
        return "❌ No tools discovered. Check Docker and Kali image availability."
    
    output = f"🔧 **Discovered Kali Tools ({len(AVAILABLE_TOOLS)} total):**\n\n"
    
    if category.strip():
        if category in TOOL_CATEGORIES and TOOL_CATEGORIES[category]:
            tools_list = TOOL_CATEGORIES[category]
            output += f"**{category} ({len(tools_list)} tools):**\n"
            for tool in sorted(tools_list)[:20]:
                output += f"  - `{tool}`\n"
            if len(tools_list) > 20:
                output += f"  - ... and {len(tools_list) - 20} more tools\n"
        else:
            available_categories = [cat for cat, tools in TOOL_CATEGORIES.items() if tools]
            output += f"❌ Category '{category}' not found. Available categories:\n"
            for cat in sorted(available_categories):
                output += f"  - {cat}\n"
    else:
        for cat_name, tools_list in TOOL_CATEGORIES.items():
            if tools_list:
                output += f"**{cat_name} ({len(tools_list)} tools):**\n"
                for tool in sorted(tools_list)[:10]:
                    output += f"  - `{tool}`\n"
                if len(tools_list) > 10:
                    output += f"  - ... and {len(tools_list) - 10} more tools\n"
                output += "\n"
    
    return output

@mcp.tool()
async def get_tool_info(tool_name: str = "") -> str:
    """Get detailed information about a specific security tool."""
    if not tool_name.strip():
        return "❌ Error: Tool name is required"
    
    sanitized_tool = sanitize_input(tool_name)
    if not sanitized_tool:
        return "❌ Error: Invalid tool name"
    
    if sanitized_tool not in AVAILABLE_TOOLS:
        return f"❌ Error: Tool '{sanitized_tool}' not found. Use `list_security_tools` to see available tools."
    
    category = AVAILABLE_TOOLS.get(sanitized_tool, "Unknown")
    
    info = f"""📋 **Tool Information: {sanitized_tool}**

**Category:** {category}

**Getting Help:**
```
run_command(command_name='{sanitized_tool}', args='--help')
```

⚠️ **Legal:** Educational use only."""
    
    return info

@mcp.tool()
async def search_tools(keyword: str = "") -> str:
    """Search for security tools by keyword."""
    if not keyword.strip():
        return "❌ Error: Search keyword is required"
    
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    keyword_lower = keyword.lower()
    matches = [(name, cat) for name, cat in AVAILABLE_TOOLS.items() if keyword_lower in name.lower()]
    
    output = f"🔍 **Search Results for '{keyword}' ({len(matches)} found):**\n\n"
    
    if matches:
        for tool_name, category in sorted(matches)[:20]:
            output += f"  - `{tool_name}` ({category})\n"
        if len(matches) > 20:
            output += f"  - ... and {len(matches) - 20} more matches\n"
    else:
        output += "No tools found.\n"
    
    return output

@mcp.tool()
async def container_status() -> str:
    """Check status of Kali containers and Docker setup."""
    try:
        ps_cmd = f"docker ps --filter name={CONTAINER_PREFIX} --format 'table {{{{.Names}}}}\\t{{{{.Status}}}}'"
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        
        output = "🐳 **Container Status:**\n\n"
        
        if result.returncode == 0 and result.stdout.strip():
            output += result.stdout
        else:
            output += "No Kali security containers currently running.\n"
        
        output += f"\n**Configuration:**\n"
        output += f"- Discovered Tools: {len(AVAILABLE_TOOLS)}\n"
        output += f"- Categories: {len(TOOL_CATEGORIES)}\n"
        
        if DISCOVERY_INFO:
            output += f"\n**Discovery Info:**\n"
            output += f"- Time: {DISCOVERY_INFO.get('discovery_time_seconds', 'N/A')}s\n"
            output += f"- Binaries Scanned: {DISCOVERY_INFO.get('binaries_found', 'N/A')}\n"
        
        return output
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def refresh_tool_discovery() -> str:
    """Force refresh of tool discovery."""
    logger.info("🔄 Forcing tool discovery refresh...")
    
    try:
        discovery_result = discover_kali_tools_optimized(force_refresh=True)
        
        if discovery_result["tools"]:
            output = f"✅ **Discovery Refreshed!**\n\n"
            output += f"**Total Tools:** {len(discovery_result['tools'])}\n"
            output += f"**Categories:** {len(discovery_result['categories'])}\n"
            output += f"**Time:** {discovery_result['discovery_info'].get('discovery_time_seconds', 'N/A')}s\n"
            return output
        else:
            return "❌ Tool discovery failed."
        
    except Exception as e:
        return f"❌ Error: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("🚀 Starting Kali Linux Security MCP Server (Unified Command Runner)...")
    logger.warning("⚠️ Educational purposes only!")
    
    # Initialize tool discovery
    initialize_tools()
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"❌ Server error: {e}", exc_info=True)
        sys.exit(1)