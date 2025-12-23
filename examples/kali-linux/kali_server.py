#!/usr/bin/env python3
"""
Dynamic Kali Linux MCP Server - All available security tools with fresh containers
"""
import os
import sys
import logging
import subprocess
import re
import json
import tempfile
import time
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("kali-server")

# Initialize MCP server - NO PROMPT PARAMETER!
mcp = FastMCP("kali-linux-everything")

# Configuration
TARGET_TIMEOUT = os.environ.get("KALI_TARGET_TIMEOUT", "120")
CONTAINER_PREFIX = os.environ.get("KALI_CONTAINER_PREFIX", "kali-mcp")
KALI_BASE_IMAGE = os.environ.get("KALI_BASE_IMAGE", "kalilinux/kali-rolling")
KALI_READY_IMAGE = os.environ.get("KALI_READY_IMAGE", "kali-mcp-ready")
SKIP_BUILD = os.environ.get("KALI_SKIP_BUILD", "false").lower() == "true"

# Global tool cache with metadata
AVAILABLE_TOOLS = {}
TOOL_CATEGORIES = {}
DISCOVERY_INFO = {}
TOOL_METADATA = {}
LAST_DISCOVERY_TIME = 0
DISCOVERY_CACHE_TTL = 3600  # 1 hour cache
TOOL_CACHE_FILE = os.environ.get("KALI_CACHE_FILE", "/mcp/kali-tools-cache.json")

def load_cached_tools():
    """Load tools from persistent cache file if it exists"""
    try:
        if os.path.exists(TOOL_CACHE_FILE):
            with open(TOOL_CACHE_FILE, 'r') as f:
                cache = json.load(f)
                logger.info(f"Loaded {len(cache.get('tools', {}))} tools from cache")
                return cache
    except Exception as e:
        logger.warning(f"Failed to load cache: {e}")
    return None

def save_cached_tools(discovery_result):
    """Save tools to persistent cache file"""
    try:
        cache_dir = os.path.dirname(TOOL_CACHE_FILE)
        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
        
        with open(TOOL_CACHE_FILE, 'w') as f:
            json.dump(discovery_result, f, indent=2)
        logger.info(f"Saved {len(discovery_result.get('tools', {}))} tools to cache at {TOOL_CACHE_FILE}")
    except Exception as e:
        logger.warning(f"Failed to save cache: {e}")

def invalidate_cache():
    """Delete the cache file to force re-discovery"""
    try:
        if os.path.exists(TOOL_CACHE_FILE):
            os.remove(TOOL_CACHE_FILE)
            logger.info(f"Cache invalidated: {TOOL_CACHE_FILE}")
            return True
    except Exception as e:
        logger.warning(f"Failed to invalidate cache: {e}")
    return False

# === UTILITY FUNCTIONS ===
def sanitize_input(input_str: str) -> str:
    """Sanitize input to prevent command injection"""
    if not input_str or not input_str.strip():
        return ""
    # Remove potentially dangerous characters
    cleaned = re.sub(r'[;&|`$()<>]', '', input_str.strip())
    # Allow safe characters for commands, files, URLs
    return re.sub(r'[^a-zA-Z0-9._\-/@:]', '', cleaned)

def is_safe_command(command: str) -> bool:
    """Check if command is safe to execute"""
    dangerous_patterns = [
        r'rm\s+/',
        r'chmod\s+777',
        r'sudo\s+su',
        r'passwd',
        r'useradd',
        r'userdel',
        r'>\s*/dev/',
        r'format',
        r'fdisk',
        r'mkfs'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return False
    return True

def build_ready_image() -> bool:
    """Build a ready-to-use Kali image with all tools pre-installed"""
    try:
        logger.info("Building ready-to-use Kali image with all tools...")
        
        # Check if image already exists
        check_cmd = f"docker images -q {KALI_READY_IMAGE}"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            logger.info(f"Ready image {KALI_READY_IMAGE} already exists")
            return True
        
        # Create temporary container for building
        build_container = f"{CONTAINER_PREFIX}-build"
        
        # Clean up any existing build container
        cleanup_cmd = f"docker stop {build_container} 2>/dev/null || true"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        # Start container
        start_cmd = f"docker run -d --name {build_container} {KALI_BASE_IMAGE} tail -f /dev/null"
        result = subprocess.run(start_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            logger.error(f"Failed to start build container: {result.stderr}")
            return False
        
        time.sleep(3)
        
        # Setup and install tools
        setup_cmd = f'''docker exec {build_container} bash -c '
export DEBIAN_FRONTEND=noninteractive
export TZ=UTC

# Update sources.list
echo "deb http://archive-4.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list
echo "deb-src http://archive-4.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list

apt-get update -qq
apt-get install -y -qq ca-certificates apt-transport-https

echo "deb https://archive-4.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list
echo "deb-src https://archive-4.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list

apt-get update -qq
apt-get install -y -qq -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" kali-linux-everything || true

apt-get clean -qq
rm -rf /var/lib/apt/lists/*
' '''
        
        logger.info("Installing kali-linux-everything (this will take a while)...")
        setup_result = subprocess.run(setup_cmd, shell=True, capture_output=True, text=True, timeout=1800)
        
        if setup_result.returncode != 0:
            logger.warning(f"Installation had warnings but continuing")
        
        # Commit the container as an image
        commit_cmd = f"docker commit {build_container} {KALI_READY_IMAGE}"
        commit_result = subprocess.run(commit_cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        if commit_result.returncode != 0:
            logger.error(f"Failed to commit image: {commit_result.stderr}")
            return False
        
        # Clean up build container
        cleanup_cmd = f"docker stop {build_container}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        logger.info(f"Successfully built ready image: {KALI_READY_IMAGE}")
        return True
        
    except Exception as e:
        logger.error(f"Error building ready image: {e}")
        return False

def setup_kali_container(container_name: str) -> str:
    """Setup Kali container with proper repositories and tools"""
    try:
        # Build or use ready image
        if not SKIP_BUILD and not build_ready_image():
            logger.warning("Failed to build ready image, using base image")
            use_image = KALI_BASE_IMAGE
        else:
            use_image = KALI_READY_IMAGE
        
        # Start container
        start_cmd = f"docker run -d --name {container_name} --rm {use_image} tail -f /dev/null"
        result = subprocess.run(start_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return f"❌ Error starting container: {result.stderr}"
        
        # Wait for container to be ready
        time.sleep(3)
        
        # Update sources.list to use Kali archive-4 mirror and install tools non-interactively
        sources_cmd = f'''docker exec {container_name} bash -c '
# Set non-interactive environment
export DEBIAN_FRONTEND=noninteractive
export TZ=UTC

# Update sources.list to use HTTP initially
echo "deb http://archive-4.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list
echo "deb-src http://archive-4.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list

# Update package lists
apt-get update -qq

# Install ca-certificates first for HTTPS support
apt-get install -y -qq ca-certificates apt-transport-https

# Switch to HTTPS mirror
echo "deb https://archive-4.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list
echo "deb-src https://archive-4.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list

# Update again with HTTPS
apt-get update -qq

# Install kali-linux-everything non-interactively with minimal output
apt-get install -y -qq -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" kali-linux-everything || true

# Clean up apt cache to reduce container size
apt-get clean -qq
rm -rf /var/lib/apt/lists/*
' '''
        
        logger.info(f"Setting up Kali container with tools: {container_name}")
        if use_image == KALI_BASE_IMAGE:
            logger.info("Installing kali-linux-everything (this will take a while)...")
            setup_result = subprocess.run(sources_cmd, shell=True, capture_output=True, text=True, timeout=1800)  # 30 minutes for full installation
            
            if setup_result.returncode != 0:
                logger.warning(f"Container setup had issues: {setup_result.stderr}")
                # Continue anyway as some tools may have been installed
            else:
                logger.info("Kali container setup completed successfully")
        else:
            logger.info("Using pre-built ready image")
        
        return ""
        
    except Exception as e:
        return f"❌ Error setting up container: {str(e)}"

def run_in_fresh_container(tool_name: str, command: str, timeout: int = 120) -> str:
    """Run command in a fresh Kali container with full tool suite"""
    container_name = f"{CONTAINER_PREFIX}-{tool_name}-{os.getpid()}-{int(time.time())}"
    
    try:
        logger.info(f"Starting fresh container: {container_name}")
        
        # Setup container with tools
        setup_error = setup_kali_container(container_name)
        if setup_error:
            return setup_error
        
        # Execute command
        exec_cmd = f"docker exec {container_name} {command}"
        logger.info(f"Executing: {exec_cmd}")
        
        result = subprocess.run(
            exec_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Clean up container
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        return format_command_output(command, result.stdout, result.stderr, result.returncode)
        
    except subprocess.TimeoutExpired:
        # Clean up on timeout
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        return f"⏱️ Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Error running command in container: {e}")
        return f"❌ Error: {str(e)}"

def format_command_output(command: str, stdout: str, stderr: str, returncode: int) -> str:
    """Format command output for display"""
    output = f"🔧 **Command:** `{command}`\n\n"
    
    if stdout.strip():
        output += f"**Output:**\n```\n{stdout}\n```\n"
    
    if stderr.strip():
        output += f"**Errors/Warnings:**\n```\n{stderr}\n```\n"
    
    if returncode == 0:
        output += "✅ **Success**"
    else:
        output += f"❌ **Failed** (exit code: {returncode})"
    
    return output

def extract_tool_metadata(tool_name: str, discovery_container: str) -> dict:
    """Extract metadata for a specific tool"""
    metadata = {
        "name": tool_name,
        "version": "Unknown",
        "description": "",
        "dependencies": [],
        "man_page_available": False,
        "help_available": False,
        "file_size": 0,
        "package": "Unknown"
    }
    
    try:
        # Get version information
        version_cmd = f"docker exec {discovery_container} {tool_name} --version 2>/dev/null || {tool_name} -V 2>/dev/null || {tool_name} version 2>/dev/null"
        version_result = subprocess.run(version_cmd, shell=True, capture_output=True, text=True, timeout=10)
        if version_result.returncode == 0 and version_result.stdout.strip():
            metadata["version"] = version_result.stdout.strip().split('\n')[0][:100]
        
        # Check if man page exists
        man_cmd = f"docker exec {discovery_container} man -w {tool_name} 2>/dev/null"
        man_result = subprocess.run(man_cmd, shell=True, capture_output=True, timeout=5)
        metadata["man_page_available"] = man_result.returncode == 0
        
        # Check help availability
        help_cmd = f"docker exec {discovery_container} {tool_name} --help 2>/dev/null | head -5"
        help_result = subprocess.run(help_cmd, shell=True, capture_output=True, text=True, timeout=5)
        metadata["help_available"] = help_result.returncode == 0 or help_result.stderr.strip()
        
        # Get file size
        which_cmd = f"docker exec {discovery_container} which {tool_name} 2>/dev/null"
        which_result = subprocess.run(which_cmd, shell=True, capture_output=True, text=True, timeout=5)
        if which_result.returncode == 0:
            size_cmd = f"docker exec {discovery_container} stat -c%s {which_result.stdout.strip()} 2>/dev/null"
            size_result = subprocess.run(size_cmd, shell=True, capture_output=True, text=True, timeout=5)
            if size_result.returncode == 0:
                try:
                    metadata["file_size"] = int(size_result.stdout.strip())
                except:
                    pass
        
        # Get package information
        dpkg_cmd = f"docker exec {discovery_container} dpkg -S {tool_name} 2>/dev/null | cut -d: -f1 | head -1"
        dpkg_result = subprocess.run(dpkg_cmd, shell=True, capture_output=True, text=True, timeout=10)
        if dpkg_result.returncode == 0:
            metadata["package"] = dpkg_result.stdout.strip()
        
    except Exception as e:
        logger.debug(f"Error extracting metadata for {tool_name}: {e}")
    
    return metadata

def detect_tool_capabilities(tool_name: str, discovery_container: str) -> list:
    """Detect what a tool can do based on its help output and common patterns"""
    capabilities = []
    
    try:
        # Get help output
        help_cmd = f"docker exec {discovery_container} {tool_name} --help 2>&1 || {tool_name} -h 2>&1"
        help_result = subprocess.run(help_cmd, shell=True, capture_output=True, text=True, timeout=15)
        help_text = (help_result.stdout + help_result.stderr).lower()
        
        # Capability detection patterns
        capability_patterns = {
            "network_scan": ["scan", "port", "network", "discover", "enum"],
            "web_testing": ["http", "web", "url", "website", "server"],
            "sql_injection": ["sql", "database", "injection", "db"],
            "password_cracking": ["password", "crack", "brute", "dictionary", "hash"],
            "wireless": ["wifi", "wireless", "bluetooth", "wlan", "air"],
            "forensics": ["forensic", "image", "recover", "carve", "analyze"],
            "reverse_engineering": ["disassemble", "decompile", "analyze", "binary"],
            "exploitation": ["exploit", "payload", "shell", "overflow"],
            "sniffing": ["sniff", "capture", "packet", "monitor"],
            "vulnerability": ["vuln", "vulnerability", "audit", "check"],
        }
        
        for capability, keywords in capability_patterns.items():
            if any(keyword in help_text for keyword in keywords):
                capabilities.append(capability)
                
    except Exception as e:
        logger.debug(f"Error detecting capabilities for {tool_name}: {e}")
    
    return capabilities

def discover_kali_tools(force_refresh: bool = False) -> dict:
    """Dynamically discover all available tools in Kali Linux using multiple methods"""
    # ALL global declarations MUST be at the top
    global LAST_DISCOVERY_TIME, AVAILABLE_TOOLS, TOOL_CATEGORIES, DISCOVERY_INFO, TOOL_METADATA
    
    current_time = time.time()
    
    # Try loading from persistent cache first
    if not force_refresh:
        # Check in-memory cache
        if (current_time - LAST_DISCOVERY_TIME) < DISCOVERY_CACHE_TTL and AVAILABLE_TOOLS:
            logger.info("Using in-memory cached tool discovery results")
            return {
                "tools": AVAILABLE_TOOLS,
                "categories": TOOL_CATEGORIES, 
                "discovery_info": DISCOVERY_INFO,
                "metadata": TOOL_METADATA
            }
        
        # Try loading from file cache
        cached = load_cached_tools()
        if cached:
            # Update global variables
            AVAILABLE_TOOLS = cached.get("tools", {})
            TOOL_CATEGORIES = cached.get("categories", {})
            DISCOVERY_INFO = cached.get("discovery_info", {})
            TOOL_METADATA = cached.get("metadata", {})
            LAST_DISCOVERY_TIME = current_time
            logger.info("Using persistent cached tool discovery results")
            return cached
    
    logger.info("Discovering Kali Linux tools...")
    
    try:
        # Start temporary container for discovery
        discovery_container = f"{CONTAINER_PREFIX}-discovery"
        
        # Clean up any existing discovery container
        cleanup_cmd = f"docker stop {discovery_container} 2>/dev/null || true"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        # Start container
        start_cmd = f"docker run -d --name {discovery_container} --rm {KALI_BASE_IMAGE} tail -f /dev/null"
        subprocess.run(start_cmd, shell=True, capture_output=True, timeout=30)
        
        time.sleep(3)
        
        # Method 1: Get all executable binaries from PATH
        get_bins_cmd = f"docker exec {discovery_container} find /usr/bin /usr/sbin /opt /usr/local/bin -type f -executable 2>/dev/null | sort"
        result = subprocess.run(get_bins_cmd, shell=True, capture_output=True, text=True, timeout=60)
        binaries = result.stdout.strip().split('\n') if result.returncode == 0 else []
        
        # Method 2: Get desktop applications
        desktop_cmd = f"docker exec {discovery_container} find /usr/share/applications -name '*.desktop' 2>/dev/null | xargs grep -l '^Exec=' 2>/dev/null | head -50"
        desktop_result = subprocess.run(desktop_cmd, shell=True, capture_output=True, text=True, timeout=30)
        desktop_files = desktop_result.stdout.strip().split('\n') if desktop_result.returncode == 0 else []
        
        # Method 3: Get installed packages
        packages_cmd = f"docker exec {discovery_container} dpkg-query -W -f='${{Package}}\\n' 2>/dev/null | sort | grep -E '(security|exploit|scan|crack|hack|pentest)'"
        packages_result = subprocess.run(packages_cmd, shell=True, capture_output=True, text=True, timeout=60)
        security_packages = packages_result.stdout.strip().split('\n') if packages_result.returncode == 0 else []
        
        # Method 4: Get tools from Kali menus/categories
        kali_categories_cmd = f"docker exec {discovery_container} find /usr/share/kali-menu -name '*.directory' 2>/dev/null | xargs basename -s .directory 2>/dev/null"
        kali_cats_result = subprocess.run(kali_categories_cmd, shell=True, capture_output=True, text=True, timeout=30)
        kali_categories = kali_cats_result.stdout.strip().split('\n') if kali_cats_result.returncode == 0 else []
        
        # Method 5: Get all Python and Perl security tools
        python_tools_cmd = f"docker exec {discovery_container} find /usr/share /opt -name '*.py' -executable 2>/dev/null | head -100"
        python_result = subprocess.run(python_tools_cmd, shell=True, capture_output=True, text=True, timeout=30)
        python_tools = python_result.stdout.strip().split('\n') if python_result.returncode == 0 else []
        
        perl_tools_cmd = f"docker exec {discovery_container} find /usr/share /opt -name '*.pl' -executable 2>/dev/null | head -50"
        perl_result = subprocess.run(perl_tools_cmd, shell=True, capture_output=True, text=True, timeout=30)
        perl_tools = perl_result.stdout.strip().split('\n') if perl_result.returncode == 0 else []
        
        tools = {}
        categories = {}
        metadata = {}
        
        # Enhanced dynamic category detection based on discovered tools
        category_keywords = {
            "Information Gathering": ["nmap", "scan", "enum", "recon", "discover", "ping", "traceroute", "dig", "dns", "whois", "host", "net", "arp", "mass", "amass", "sublist", "fierce", "dnsenum", "dnsrecon"],
            "Web Application Analysis": ["nikto", "sqlmap", "wpscan", "dirb", "gobuster", "wfuzz", "ffuf", "burp", "zap", "skipfish", "arachni", "whatweb", "joomscan", "droopescan", "cmseek", "aquatone", "subfinder", "fierce", "gobuster"],
            "Vulnerability Analysis": ["openvas", "nessus", "nexpose", "vuln", "audit", "check", "test", "lynis", "chkrootkit", "rkhunter"],
            "Database Assessment": ["sql", "database", "mysql", "postgres", "oracle", "mdb", "db", "sqlninja", "sqlmate", "bbsql"],
            "Password Attacks": ["john", "hashcat", "hydra", "medusa", "ncrack", "patator", "crowbar", "cewl", "crunch", "mask", "wordlist", "rainbow", "ophcrack", "thc-pptp-bruter"],
            "Wireless Attacks": ["aircrack", "wifi", "bluetooth", "kismet", "wifite", "fern", "bettercap", "airodump", "aireplay", "airmon", "bluesnarfer", "cowpatty"],
            "Reverse Engineering": ["radare", "ghidra", "gdb", "objdump", "strace", "ltrace", "readelf", "strings", "hexdump", "binwalk", "yara", "volatility", "foremost", "disasm", "edb-debugger"],
            "Exploitation Tools": ["metasploit", "msf", "exploit", "payload", "shell", "bind", "reverse", "beef", "setoolkit", "empire", "cobaltstrike", "powercat", "netcat", "socat", "pwncat", "armitage"],
            "Sniffing & Spoofing": ["wireshark", "tcpdump", "tshark", "dsniff", "arpspoof", "dnsspoof", "ettercap", "mitm", "sslstrip", "macof", "ngrep", "wireshark-qt"],
            "Forensics": ["autopsy", "sleuthkit", "volatility", "dd", "guymager", "photorec", "testdisk", "scalpel", "extundelete", "exiftool", "log2timeline", "plaso", "image", "recover", "bulk-extractor"],
            "Social Engineering": ["setoolkit", "gophish", "king", "evilginx", "modlishka", "creepy", "maltego", "recon-ng", "theharvester", "inforiver", "shodan", "sploit", "smtp-user-enum"],
            "Reporting Tools": ["report", "dradis", "cutycapt", "evidence", "faraday", "keimpx"],
            "Post Exploitation": ["priv", "escalat", "persist", "maintain", "lateral", "pivot", "tunnel", "peass", "linpeas", "winpeas"],
            "System Services": ["curl", "wget", "git", "python", "perl", "ruby", "bash", "sh", "netcat", "nc", "ssh", "ftp", "tftp", "openssl"]
        }
        
        # Initialize categories
        for category in category_keywords.keys():
            categories[category] = []
        
        # Process all discovered tools with enhanced metadata
        all_discovered_tools = set()
        processed_tools = 0
        max_tools_to_process = 500  # Limit to prevent excessive processing time
        
        # Process binaries with metadata extraction
        for binary in binaries[:max_tools_to_process]:
            if binary.strip():
                tool_name = binary.split('/')[-1]
                all_discovered_tools.add(tool_name)
                
                # Extract metadata for important tools
                if any(keyword in tool_name.lower() for keywords in [cat_keywords for cat_keywords in category_keywords.values()] for keyword in keywords):
                    tool_metadata = extract_tool_metadata(tool_name, discovery_container)
                    metadata[tool_name] = tool_metadata
                    processed_tools += 1
                
                # Enhanced categorization based on keywords and capabilities
                categorized = False
                for category, keywords in category_keywords.items():
                    if any(keyword in tool_name.lower() for keyword in keywords):
                        if category not in categories:
                            categories[category] = []
                        categories[category].append(tool_name)
                        tools[tool_name] = category
                        categorized = True
                        break
                
                # If not categorized by keywords, try capability detection for uncategorized tools
                if not categorized and tool_name not in ["python3", "python", "perl", "ruby", "bash", "sh", "rm", "chmod", "sudo", "apt", "apt-get"]:
                    capabilities = detect_tool_capabilities(tool_name, discovery_container)
                    if capabilities:
                        # Categorize based on detected capabilities
                        cap_mapping = {
                            "network_scan": "Information Gathering",
                            "web_testing": "Web Application Analysis", 
                            "sql_injection": "Database Assessment",
                            "password_cracking": "Password Attacks",
                            "wireless": "Wireless Attacks",
                            "forensics": "Forensics",
                            "reverse_engineering": "Reverse Engineering",
                            "exploitation": "Exploitation Tools",
                            "sniffing": "Sniffing & Spoofing",
                            "vulnerability": "Vulnerability Analysis"
                        }
                        
                        for capability in capabilities:
                            if capability in cap_mapping:
                                category = cap_mapping[capability]
                                if category not in categories:
                                    categories[category] = []
                                categories[category].append(tool_name)
                                tools[tool_name] = category
                                categorized = True
                                break
                
                # If still not categorized, add to System Services
                if not categorized and tool_name not in ["python3", "python", "perl", "ruby", "bash", "sh", "rm", "chmod", "sudo"]:
                    if "System Services" not in categories:
                        categories["System Services"] = []
                    categories["System Services"].append(tool_name)
                    tools[tool_name] = "System Services"
        
        # Process desktop applications
        for desktop_file in desktop_files:
            if desktop_file.strip():
                try:
                    # Extract Exec line from desktop file
                    exec_cmd = f"docker exec {discovery_container} grep '^Exec=' '{desktop_file}' 2>/dev/null | cut -d= -f2 | cut -d' ' -f1"
                    exec_result = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=10)
                    
                    if exec_result.returncode == 0:
                        app_binary = exec_result.stdout.strip()
                        if app_binary and app_binary not in all_discovered_tools:
                            all_discovered_tools.add(app_binary)
                            # Categorize desktop apps
                            if any(keyword in desktop_file.lower() for keyword in ["security", "network", "forensic", "exploit"]):
                                if "Information Gathering" not in categories:
                                    categories["Information Gathering"] = []
                                categories["Information Gathering"].append(app_binary)
                                tools[app_binary] = "Information Gathering"
                except:
                    continue
        
        # Process Python tools
        for py_tool in python_tools:
            if py_tool.strip():
                tool_name = py_tool.split('/')[-1].replace('.py', '')
                if tool_name and tool_name not in all_discovered_tools:
                    all_discovered_tools.add(tool_name)
                    categories["Web Application Analysis"].append(tool_name)
                    tools[tool_name] = "Web Application Analysis"
        
        # Process Perl tools
        for pl_tool in perl_tools:
            if pl_tool.strip():
                tool_name = pl_tool.split('/')[-1].replace('.pl', '')
                if tool_name and tool_name not in all_discovered_tools:
                    all_discovered_tools.add(tool_name)
                    categories["Web Application Analysis"].append(tool_name)
                    tools[tool_name] = "Web Application Analysis"
        
        # Remove empty categories
        categories = {k: v for k, v in categories.items() if v}
        
        # Add metadata about discovery methods
        discovery_info = {
            "binaries_found": len([b for b in binaries if b.strip()]),
            "desktop_apps_found": len([d for d in desktop_files if d.strip()]),
            "security_packages": len([p for p in security_packages if p.strip()]),
            "kali_categories": len([k for k in kali_categories if k.strip()]),
            "python_tools": len([p for p in python_tools if p.strip()]),
            "perl_tools": len([p for p in perl_tools if p.strip()])
        }
        
        # Log discovery statistics
        logger.info(f"Discovery completed:")
        logger.info(f"  - Binaries: {discovery_info['binaries_found']}")
        logger.info(f"  - Desktop apps: {discovery_info['desktop_apps_found']}")
        logger.info(f"  - Security packages: {discovery_info['security_packages']}")
        logger.info(f"  - Python tools: {discovery_info['python_tools']}")
        logger.info(f"  - Perl tools: {discovery_info['perl_tools']}")
        logger.info(f"  - Total categorized tools: {len(tools)} in {len(categories)} categories")
        
        # Add metadata to discovery info
        discovery_info["tools_processed"] = processed_tools
        discovery_info["tools_with_metadata"] = len(metadata)
        
        # Clean up discovery container
        cleanup_cmd = f"docker stop {discovery_container}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        # Update global cache
        AVAILABLE_TOOLS = tools
        TOOL_CATEGORIES = categories
        DISCOVERY_INFO = discovery_info
        TOOL_METADATA = metadata
        LAST_DISCOVERY_TIME = current_time
        
        # Save to persistent cache
        result = {"tools": tools, "categories": categories, "discovery_info": discovery_info, "metadata": metadata}
        save_cached_tools(result)
        
        return result
    except Exception as e:
        logger.error(f"Error discovering tools: {e}")
        return {"tools": {}, "categories": {}, "discovery_info": {}}

def initialize_tools():
    """Initialize available tools on startup"""
    global AVAILABLE_TOOLS, TOOL_CATEGORIES, DISCOVERY_INFO
    discovery_result = discover_kali_tools()
    AVAILABLE_TOOLS = discovery_result["tools"]
    TOOL_CATEGORIES = discovery_result["categories"]
    DISCOVERY_INFO = discovery_result.get("discovery_info", {})

# === DYNAMIC MCP TOOLS ===

def create_tool_function(tool_name: str, category: str):
    """Create a dynamic tool function for each security tool"""
    async def tool_function(command_args: str = "", help_flag: str = "") -> str:
        """Execute security tool with arguments - use --help for usage information."""
        logger.info(f"Executing {tool_name} with args: {command_args}")
        
        if help_flag == "--help" or not command_args.strip():
            # Get help for the tool
            help_command = f"{tool_name} --help 2>&1 || {tool_name} -h 2>&1 || {tool_name} 2>&1"
            return run_in_fresh_container(tool_name, help_command, timeout=30)
        
        # Sanitize command arguments
        sanitized_args = sanitize_input(command_args)
        if not sanitized_args:
            return f"❌ Error: Invalid command arguments"
        
        # Build full command
        full_command = f"{tool_name} {sanitized_args}"
        
        # Check if command is safe
        if not is_safe_command(full_command):
            return "❌ Error: Command contains potentially dangerous operations"
        
        # Execute with appropriate timeout based on tool category
        timeout = TARGET_TIMEOUT
        if category in ["Exploitation Tools", "Password Attacks"]:
            timeout = 300  # Longer timeout for intensive tools
        elif category in ["Wireless Attacks", "Forensics"]:
            timeout = 180
        
        return run_in_fresh_container(tool_name, full_command, timeout=int(timeout))
    
    tool_function.__name__ = f"execute_{tool_name.replace('-', '_')}"
    tool_function.__doc__ = f"Execute {tool_name} security tool - use --help for usage"
    return tool_function

# === STATIC MCP TOOLS ===

@mcp.tool()
async def list_security_tools(category: str = "") -> str:
    """List all available security tools, optionally filtered by category."""
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    if not AVAILABLE_TOOLS:
        return "❌ No tools discovered. Check Docker and Kali image availability."
    
    output = f"🔧 **Kali Linux Security Tools ({len(AVAILABLE_TOOLS)} total):**\n\n"
    
    if category.strip():
        if category in TOOL_CATEGORIES and TOOL_CATEGORIES[category]:
            tools_list = TOOL_CATEGORIES[category]
            output += f"**{category} ({len(tools_list)} tools):**\n"
            for tool in sorted(tools_list):
                output += f"  - `{tool}`\n"
        else:
            available_categories = [cat for cat, tools in TOOL_CATEGORIES.items() if tools]
            output += f"❌ Category '{category}' not found. Available categories:\n"
            for cat in sorted(available_categories):
                output += f"  - {cat}\n"
    else:
        for cat_name, tools_list in TOOL_CATEGORIES.items():
            if tools_list:
                output += f"**{cat_name} ({len(tools_list)} tools):**\n"
                for tool in sorted(tools_list)[:10]:  # Show first 10 to avoid clutter
                    output += f"  - `{tool}`\n"
                if len(tools_list) > 10:
                    output += f"  - ... and {len(tools_list) - 10} more tools\n"
                output += "\n"
    
    output += "\n💡 **Usage:** Execute any tool by calling its name (e.g., `nmap --help`)"
    return output

@mcp.tool()
async def get_tool_info(tool_name: str = "") -> str:
    """Get detailed information about a specific security tool."""
    if not tool_name.strip():
        return "❌ Error: Tool name is required"
    
    sanitized_tool = sanitize_input(tool_name.replace("-", "_"))
    if not sanitized_tool:
        return "❌ Error: Invalid tool name"
    
    # Restore original tool name
    actual_tool_name = sanitized_tool.replace("_", "-")
    
    if actual_tool_name not in AVAILABLE_TOOLS:
        # Try to find case-insensitive match
        for tool in AVAILABLE_TOOLS:
            if tool.lower() == actual_tool_name.lower():
                actual_tool_name = tool
                break
        else:
            return f"❌ Error: Tool '{actual_tool_name}' not found. Use `list_security_tools` to see available tools."
    
    category = AVAILABLE_TOOLS.get(actual_tool_name, "Unknown")
    
    info = f"""📋 **Tool Information: {actual_tool_name}**

**Category:** {category}

**Getting Help:**
```
{actual_tool_name} --help
```

**Quick Usage Examples:"""
    
    # Add usage examples based on tool
    if actual_tool_name == "nmap":
        info += """
- Basic port scan: `nmap -p 1-1000 target.com`
- Service detection: `nmap -sV target.com`
- Aggressive scan: `nmap -A target.com`
- OS detection: `nmap -O target.com`"""
    elif actual_tool_name == "nikto":
        info += """
- Basic web scan: `nikto -h http://target.com`
- Specific port: `nikto -h target.com -p 8080`
- Save output: `nikto -h target.com -o output.html`"""
    elif actual_tool_name == "sqlmap":
        info += """
- Basic scan: `sqlmap -u "http://target.com/page.php?id=1"`
- Database enumeration: `sqlmap -u "URL" --dbs`
- Dump data: `sqlmap -u "URL" -D dbname -T tablename --dump`"""
    elif actual_tool_name == "wpscan":
        info += """
- Basic scan: `wpscan --url http://target.com`
- Enumerate users: `wpscan --url URL --enumerate u`
- Plugin scan: `wpscan --url URL --enumerate p`"""
    elif actual_tool_name == "dirb":
        info += """
- Basic scan: `dirb http://target.com`
- Custom wordlist: `dirb http://target.com /path/to/wordlist`
- Specific extensions: `dirb http://target.com -x .php,.html`"""
    elif actual_tool_name == "searchsploit":
        info += """
- Search exploits: `searchsploit apache 2.4`
- Exact match: `searchsploit --exact "Apache 2.4.49"`
- Copy exploit: `searchsploit -m exploit/path/exploit.py`"""
    elif actual_tool_name == "hydra":
        info += """
- SSH brute force: `hydra -l admin -P wordlist.txt ssh://target.com`
- HTTP form: `hydra -l admin -P wordlist.txt target.com http-post-form "/login:username=^USER^&password=^PASS^"`"""
    elif actual_tool_name == "john":
        info += """
- Basic cracking: `john hash.txt`
- Wordlist mode: `john --wordlist=wordlist.txt hash.txt`
- Show results: `john --show hash.txt`"""
    elif actual_tool_name == "hashcat":
        info += """
- Basic attack: `hashcat -m 0 hash.txt wordlist.txt`
- Show cracked: `hashcat -m 0 hash.txt --show`
- GPU acceleration: `hashcat -m 0 -d 1 hash.txt wordlist.txt`"""
    else:
        info += f"""
- Get help: `{actual_tool_name} --help`
- Basic usage: `{actual_tool_name} [options] [target]`"""
    
    info += f"""

**Safety Note:** Only use on systems you own or have permission to test.

⚠️ **Legal:** Educational use only."""
    
    return info

@mcp.tool()
async def container_status() -> str:
    """Check status of Kali MCP containers and Docker setup."""
    try:
        # Check running containers
        ps_cmd = f"docker ps --filter name={CONTAINER_PREFIX} --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'"
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        
        output = "🐳 **Container Status:**\n\n"
        
        if result.returncode == 0 and result.stdout.strip():
            output += result.stdout
        else:
            output += "No Kali MCP containers currently running.\n"
        
        # Check Docker and Kali image
        docker_version = subprocess.run("docker --version", shell=True, capture_output=True, text=True)
        if docker_version.returncode == 0:
            output += f"\n**Docker:** {docker_version.stdout.strip()}"
        
        # Check both base and ready images
        base_check = subprocess.run(f"docker images {KALI_BASE_IMAGE}", shell=True, capture_output=True, text=True)
        ready_check = subprocess.run(f"docker images {KALI_READY_IMAGE}", shell=True, capture_output=True, text=True)
        
        if ready_check.returncode == 0:
            output += f"\n**Kali Ready Image:** Available ({KALI_READY_IMAGE}) ✅"
        elif base_check.returncode == 0:
            output += f"\n**Kali Base Image:** Available ({KALI_BASE_IMAGE}) - will build ready image"
        else:
            output += f"\n**Kali Images:** Not found - will pull on first use"
        
        # Configuration info
        output += f"\n\n**Configuration:**\n"
        output += f"- Timeout: {TARGET_TIMEOUT}s\n"
        output += f"- Container Prefix: {CONTAINER_PREFIX}\n"
        output += f"- Base Image: {KALI_BASE_IMAGE}\n"
        output += f"- Ready Image: {KALI_READY_IMAGE}\n"
        output += f"- Skip Build: {SKIP_BUILD}\n"
        output += f"- Discovered Tools: {len(AVAILABLE_TOOLS)}\n"
        
        # Add discovery statistics
        if DISCOVERY_INFO:
            output += f"\n**Discovery Statistics:**\n"
            output += f"- Binaries found: {DISCOVERY_INFO.get('binaries_found', 'N/A')}\n"
            output += f"- Desktop applications: {DISCOVERY_INFO.get('desktop_apps_found', 'N/A')}\n"
            output += f"- Security packages: {DISCOVERY_INFO.get('security_packages', 'N/A')}\n"
            output += f"- Python tools: {DISCOVERY_INFO.get('python_tools', 'N/A')}\n"
            output += f"- Perl tools: {DISCOVERY_INFO.get('perl_tools', 'N/A')}\n"
            output += f"- Categories created: {len(TOOL_CATEGORIES)}\n"
        
        return output
    except Exception as e:
        logger.error(f"Error checking container status: {e}")
        return f"❌ Error checking status: {str(e)}"

@mcp.tool()
async def refresh_tool_discovery() -> str:
    """Force refresh of tool discovery to find new tools and update metadata. This invalidates the cache."""
    logger.info("Forcing tool discovery refresh...")
    
    try:
        # Invalidate persistent cache
        invalidate_cache()
        
        discovery_result = discover_kali_tools(force_refresh=True)
        
        if discovery_result["tools"]:
            output = f"🔄 **Tool Discovery Refreshed Successfully!**\n\n"
            output += f"**Cache invalidated and rebuilt**\n"
            output += f"**Total Tools Discovered:** {len(discovery_result['tools'])}\n"
            output += f"**Categories:** {len(discovery_result['categories'])}\n\n"
            
            if 'discovery_info' in discovery_result:
                info = discovery_result['discovery_info']
                output += f"**Discovery Statistics:**\n"
                output += f"- Binaries found: {info.get('binaries_found', 'N/A')}\n"
                output += f"- Desktop applications: {info.get('desktop_apps_found', 'N/A')}\n"
                output += f"- Security packages: {info.get('security_packages', 'N/A')}\n"
                output += f"- Python tools: {info.get('python_tools', 'N/A')}\n"
                output += f"- Perl tools: {info.get('perl_tools', 'N/A')}\n"
                output += f"- Tools with metadata: {info.get('tools_with_metadata', 'N/A')}\n\n"
            
            output += "**Available Categories:**\n"
            for category, tools in discovery_result['categories'].items():
                if tools:
                    output += f"- {category}: {len(tools)} tools\n"
            
            output += f"\n💡 **Tip:** Use `list_security_tools` to see all tools or `get_tool_info` for details."
        else:
            output = "❌ Tool discovery failed. Check Docker and Kali image availability."
        
        return output
        
    except Exception as e:
        logger.error(f"Error refreshing tool discovery: {e}")
        return f"❌ Error refreshing discovery: {str(e)}"

@mcp.tool()
async def get_tool_metadata(tool_name: str = "") -> str:
    """Get detailed metadata for a specific security tool."""
    if not tool_name.strip():
        return "❌ Error: Tool name is required"
    
    sanitized_tool = sanitize_input(tool_name.replace("-", "_"))
    if not sanitized_tool:
        return "❌ Error: Invalid tool name"
    
    actual_tool_name = sanitized_tool.replace("_", "-")
    
    if actual_tool_name not in AVAILABLE_TOOLS:
        return f"❌ Error: Tool '{actual_tool_name}' not found. Use `list_security_tools` to see available tools."
    
    metadata = TOOL_METADATA.get(actual_tool_name, {})
    category = AVAILABLE_TOOLS.get(actual_tool_name, "Unknown")
    
    output = f"📋 **Enhanced Tool Metadata: {actual_tool_name}**\n\n"
    output += f"**Category:** {category}\n"
    
    if metadata:
        output += f"**Version:** {metadata.get('version', 'Unknown')}\n"
        output += f"**Package:** {metadata.get('package', 'Unknown')}\n"
        output += f"**File Size:** {metadata.get('file_size', 0)} bytes\n"
        output += f"**Man Page Available:** {'✅' if metadata.get('man_page_available') else '❌'}\n"
        output += f"**Help Available:** {'✅' if metadata.get('help_available') else '❌'}\n"
        
        if metadata.get('dependencies'):
            output += f"**Dependencies:** {', '.join(metadata['dependencies'])}\n"
    else:
        output += "**Metadata:** Not available\n"
    
    output += f"\n**Usage:** `{actual_tool_name} --help`\n"
    output += f"\n⚠️ **Legal:** Educational use only."
    
    return output

@mcp.tool()
async def search_tools(keyword: str = "") -> str:
    """Search for security tools by keyword or pattern."""
    if not keyword.strip():
        return "❌ Error: Search keyword is required"
    
    if not AVAILABLE_TOOLS:
        initialize_tools()
    
    keyword_lower = keyword.lower()
    matches = []
    
    for tool_name, category in AVAILABLE_TOOLS.items():
        if keyword_lower in tool_name.lower():
            matches.append((tool_name, category))
    
    output = f"🔍 **Search Results for '{keyword}' ({len(matches)} found):**\n\n"
    
    if matches:
        for tool_name, category in sorted(matches):
            metadata = TOOL_METADATA.get(tool_name, {})
            version = metadata.get('version', 'Unknown')[:20] if metadata.get('version') else 'Unknown'
            output += f"  - `{tool_name}` ({category}) - v{version}\n"
    else:
        output += "No tools found matching your search.\n"
        output += f"\n💡 **Tip:** Use `list_security_tools` to see all available tools."
    
    return output

@mcp.tool()
async def install_tool(package_name: str = "", tool_type: str = "apt") -> str:
    """Install additional security tools in the Kali Linux environment.
    
    Args:
        package_name: Name of the package to install (e.g., 'nikto', 'beef-xss')
        tool_type: Installation method - 'apt' (default), 'pip', 'gem', 'go'
    """
    logger.info(f"Installing tool: {package_name} via {tool_type}")
    
    if not package_name.strip():
        return "❌ Error: Package name is required"
    
    # Sanitize inputs
    sanitized_package = sanitize_input(package_name)
    if not sanitized_package:
        return "❌ Error: Invalid package name"
    
    sanitized_type = sanitize_input(tool_type)
    valid_types = ["apt", "pip", "pip3", "gem", "go", "npm"]
    if sanitized_type not in valid_types:
        return f"❌ Error: Invalid tool type. Valid types: {', '.join(valid_types)}"
    
    try:
        # Create installation container
        container_name = f"{CONTAINER_PREFIX}-install-{os.getpid()}-{int(time.time())}"
        
        output = f"📦 **Installing {sanitized_package} via {sanitized_type}...**\n\n"
        
        # Setup container
        setup_error = setup_kali_container(container_name)
        if setup_error:
            return setup_error
        
        # Build installation command based on type
        if sanitized_type == "apt":
            install_cmd = f"""bash -c '
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq
                apt-get install -y -qq {sanitized_package}
                apt-get clean -qq
            '"""
        elif sanitized_type in ["pip", "pip3"]:
            install_cmd = f"pip3 install {sanitized_package}"
        elif sanitized_type == "gem":
            install_cmd = f"gem install {sanitized_package}"
        elif sanitized_type == "go":
            install_cmd = f"go install {sanitized_package}"
        elif sanitized_type == "npm":
            install_cmd = f"npm install -g {sanitized_package}"
        
        # Execute installation
        exec_cmd = f"docker exec {container_name} {install_cmd}"
        logger.info(f"Running: {exec_cmd}")
        
        result = subprocess.run(
            exec_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout for installation
        )
        
        # Commit the container as new ready image to persist the installation
        if result.returncode == 0:
            commit_cmd = f"docker commit {container_name} {KALI_READY_IMAGE}"
            commit_result = subprocess.run(commit_cmd, shell=True, capture_output=True, text=True, timeout=60)
            
            if commit_result.returncode == 0:
                output += f"✅ **Successfully installed {sanitized_package}**\n\n"
                output += f"**Installation output:**\n```\n{result.stdout}\n```\n"
                output += f"\n✅ Changes saved to {KALI_READY_IMAGE}\n"
                output += f"💡 **Tip:** Run `refresh_tool_discovery` to find newly installed tools"
            else:
                output += f"⚠️ **Tool installed but failed to save changes**\n"
                output += f"Commit error: {commit_result.stderr}\n"
                output += f"Tool will be available in current container only"
        else:
            output += f"❌ **Installation failed**\n\n"
            output += f"**Error:**\n```\n{result.stderr}\n```\n"
            output += f"\n💡 **Tip:** Check package name and try different tool_type"
        
        # Cleanup
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        return output
        
    except subprocess.TimeoutExpired:
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        return f"⏱️ Installation timed out after 5 minutes"
    except Exception as e:
        logger.error(f"Error installing tool: {e}")
        return f"❌ Error: {str(e)}"


# === DYNAMIC TOOL REGISTRATION ===
def register_dynamic_tools():
    """Dynamically register all discovered tools as MCP tools"""
    initialize_tools()
    
    for tool_name, category in AVAILABLE_TOOLS.items():
        # Skip system tools that shouldn't be directly exposed
        if tool_name in ["python3", "python", "bash", "sh", "rm", "chmod"]:
            continue
        
        # Create dynamic tool function
        tool_func = create_tool_function(tool_name, category)
        
        # Register with MCP
        mcp.tool()(tool_func)
        
        logger.info(f"Registered tool: {tool_name} ({category})")

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting Dynamic Kali Linux MCP Server...")
    logger.warning("This server is for educational purposes only. Only test on systems you own or have permission to test.")
    
    # Register all dynamic tools
    register_dynamic_tools()
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
