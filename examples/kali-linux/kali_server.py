#!/usr/bin/env python3
"""
Kali Linux Security MCP Server - DIRECT EXECUTION VERSION
Fixed version that runs commands directly instead of using Docker containers.
Since we're already running inside a Kali container, we can execute tools directly.
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
    """Sanitize input to prevent command injection but allow whitespace in args"""
    if not input_str or not input_str.strip():
        return ""
    # Remove only dangerous characters, but preserve spaces and standard command characters
    cleaned = re.sub(r'[;&|`$()]', '', input_str.strip())
    # Allow alphanumerics, spaces, hyphens, underscores, forward slashes, dots, @, colons, quotes
    return re.sub(r'[^a-zA-Z0-9._\-/@:\s"\'\[\]]', '', cleaned)

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

def run_security_command_direct(command_name: str, args: str, timeout: int = 120) -> str:
    """Run security command directly in the current container (FIXED VERSION - NO DOCKER)"""
    try:
        sanitized_args = sanitize_input(args)
        full_command = f"{command_name} {sanitized_args}".strip()
        
        if not is_safe_command(full_command):
            return "❌ Error: Command contains potentially dangerous operations"
        
        logger.info(f"Executing directly: {full_command}")
        
        # FIXED: Run command directly instead of using Docker exec
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=timeout)
        
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
        return f"⏱️ Command timed out after {timeout} seconds"
    except FileNotFoundError:
        return f"❌ Error: Command '{command_name}' not found. Use list_commands() to see available tools."
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
        return run_security_command_direct(command_name, args, timeout)
    
    # PRIORITY 2: Allow any command in PATH (not just discovered ones)
    # This makes it more flexible for tools that might not be categorized
    try:
        # Check if command exists in PATH
        check_cmd = f"which {command_name}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logger.info(f"✅ Executing undetected tool: {command_name}")
            return run_security_command_direct(command_name, args, SECURITY_TIMEOUT)
    except:
        pass
    
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
    
    # Add discovered commands
    for cmd_name, cat in AVAILABLE_TOOLS.items():
        if cat not in all_commands:
            all_commands[cat] = []
        all_commands[cat].append((cmd_name, {"description": f"Kali security tool", "category": cat}))
    
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
                for cmd_name, cmd_def in commands[:15]:  # Show first 15 tools
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
    
    # Check if it's a discovered tool
    if command_name in AVAILABLE_TOOLS:
        category = AVAILABLE_TOOLS[command_name]
        
        output = f"📋 **Command Information: {command_name}**\n\n"
        output += f"**Description:** Kali security tool\n"
        output += f"**Category:** {category}\n"
        output += f"**Status:** Available (discovered)\n"
        
        # Try to get help information
        try:
            help_result = subprocess.run(f"{command_name} --help", shell=True, capture_output=True, text=True, timeout=10)
            if help_result.returncode == 0 and help_result.stdout.strip():
                help_lines = help_result.stdout.strip().split('\n')[:5]
                output += f"\n**Help Preview:**\n```\n" + "\n".join(help_lines) + "\n```\n"
        except:
            pass
        
        output += f"\n**Example Usage:**\n```\nrun_command(command_name='{command_name}', args='--help')\n```"
        
        return output
    
    # Try to get basic info for any command in PATH
    try:
        check_cmd = f"which {command_name}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            output = f"📋 **Command Information: {command_name}**\n\n"
            output += f"**Description:** Available command\n"
            output += f"**Location:** {result.stdout.strip()}\n"
            output += f"**Status:** Available (in PATH)\n"
            output += f"\n**Example Usage:**\n```\nrun_command(command_name='{command_name}', args='--help')\n```"
            return output
    except:
        pass
    
    return f"❌ Error: Command '{command_name}' not found. Use list_commands() to see available tools."

@mcp.tool()
async def search_tools(keyword: str = "") -> str:
    """Search for tools by keyword."""
    if not keyword.strip():
        return "❌ Error: keyword is required"
    
    # Ensure tools are discovered
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    keyword = keyword.lower()
    matching_tools = []
    
    for tool_name, category in AVAILABLE_TOOLS.items():
        if keyword in tool_name.lower() or keyword in category.lower():
            matching_tools.append((tool_name, category))
    
    if not matching_tools:
        return f"❌ No tools found matching '{keyword}'. Try a different keyword."
    
    output = f"🔍 **Tools matching '{keyword}':**\n\n"
    
    # Group by category
    by_category = {}
    for tool_name, category in matching_tools:
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(tool_name)
    
    for category, tools in sorted(by_category.items()):
        output += f"**{category}** ({len(tools)} tools):\n"
        for tool_name in sorted(tools):
            output += f"  - `{tool_name}`\n"
        output += "\n"
    
    output += f"\n💡 Use `run_command(command_name='tool_name', args='--help')` for tool details"
    return output

@mcp.tool()
async def container_status() -> str:
    """Get current container status and discovery information."""
    # Ensure tools are discovered
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    output = f"🐳 **Kali Security Container Status:**\n\n"
    output += f"**Status:** ✅ Running directly (no Docker needed)\n"
    output += f"**Execution Mode:** Direct command execution\n"
    output += f"**Discovered Tools:** {len(AVAILABLE_TOOLS)}\n"
    output += f"**Categories:** {len(TOOL_CATEGORIES)}\n"
    
    if DISCOVERY_INFO:
        output += f"\n**Discovery Info:**\n"
        output += f"- Binaries Scanned: {DISCOVERY_INFO.get('binaries_found', 'N/A')}\n"
        output += f"- Tools Categorized: {DISCOVERY_INFO.get('tools_categorized', 'N/A')}\n"
        output += f"- Discovery Time: {DISCOVERY_INFO.get('discovery_time_seconds', 'N/A')}s\n"
    
    if TOOL_CATEGORIES:
        output += f"\n**Categories Breakdown:**\n"
        for cat, tools in sorted(TOOL_CATEGORIES.items()):
            output += f"- {cat}: {len(tools)} tools\n"
    
    output += f"\n💡 **Tip:** This container runs commands directly - no additional Docker overhead!"
    return output

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("🚀 Starting Kali Linux Security MCP Server (Direct Execution Version)...")
    
    # Initialize tools on startup
    initialize_tools()
    logger.info(f"📊 Loaded {len(AVAILABLE_TOOLS)} tools in {len(TOOL_CATEGORIES)} categories")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"❌ Server error: {e}", exc_info=True)
        sys.exit(1)