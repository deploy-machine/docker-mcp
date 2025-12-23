#!/usr/bin/env python3
"""
Dynamic Kali Linux MCP Server - OPTIMIZED VERSION with multithreading
Performance improvements:
- Parallel tool discovery using ThreadPoolExecutor
- Lazy metadata extraction (only when requested)
- Progress logging for visibility
- Optimized file system scanning
"""
import os
import sys
import logging
import subprocess
import re
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("kali-server")

# Initialize MCP server
mcp = FastMCP("kali-linux-everything")

# Configuration
TARGET_TIMEOUT = os.environ.get("KALI_TARGET_TIMEOUT", "120")
CONTAINER_PREFIX = os.environ.get("KALI_CONTAINER_PREFIX", "kali-mcp")
KALI_BASE_IMAGE = os.environ.get("KALI_BASE_IMAGE", "kali-security-mcp-server:latest")
MAX_WORKERS = int(os.environ.get("KALI_DISCOVERY_WORKERS", "10"))  # Parallel workers

# Global tool cache with metadata
AVAILABLE_TOOLS = {}
TOOL_CATEGORIES = {}
DISCOVERY_INFO = {}
TOOL_METADATA = {}
LAST_DISCOVERY_TIME = 0
DISCOVERY_CACHE_TTL = 3600  # 1 hour cache
TOOL_CACHE_FILE = os.environ.get("KALI_CACHE_FILE", "/mcp/kali-tools-cache.json")

# Thread-safe lock for updating global state
discovery_lock = Lock()

def load_cached_tools():
    """Load tools from persistent cache file if it exists"""
    try:
        if os.path.exists(TOOL_CACHE_FILE):
            with open(TOOL_CACHE_FILE, 'r') as f:
                cache = json.load(f)
                logger.info(f"✅ Loaded {len(cache.get('tools', {}))} tools from cache")
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
        logger.info(f"💾 Saved {len(discovery_result.get('tools', {}))} tools to cache")
    except Exception as e:
        logger.warning(f"Failed to save cache: {e}")

def invalidate_cache():
    """Delete the cache file to force re-discovery"""
    try:
        if os.path.exists(TOOL_CACHE_FILE):
            os.remove(TOOL_CACHE_FILE)
            logger.info(f"🗑️ Cache invalidated: {TOOL_CACHE_FILE}")
            return True
    except Exception as e:
        logger.warning(f"Failed to invalidate cache: {e}")
    return False

# === UTILITY FUNCTIONS ===
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

def setup_kali_container(container_name: str) -> str:
    """Setup Kali container"""
    try:
        logger.info(f"Starting Kali container: {container_name}")
        start_cmd = f"docker run -d --name {container_name} --rm --cap-add=NET_RAW --cap-add=NET_ADMIN {KALI_BASE_IMAGE} tail -f /dev/null"
        result = subprocess.run(start_cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return f"❌ Error starting container: {result.stderr}"
        
        time.sleep(2)
        logger.info(f"Container {container_name} ready")
        return ""
        
    except Exception as e:
        return f"❌ Error setting up container: {str(e)}"

def run_in_fresh_container(tool_name: str, command: str, timeout: int = 120) -> str:
    """Run command in a fresh Kali container"""
    container_name = f"{CONTAINER_PREFIX}-{tool_name}-{os.getpid()}-{int(time.time())}"
    
    try:
        setup_error = setup_kali_container(container_name)
        if setup_error:
            return setup_error
        
        exec_cmd = f"docker exec {container_name} {command}"
        logger.info(f"Executing: {exec_cmd}")
        
        result = subprocess.run(exec_cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        
        return format_command_output(command, result.stdout, result.stderr, result.returncode)
        
    except subprocess.TimeoutExpired:
        cleanup_cmd = f"docker stop {container_name}"
        subprocess.run(cleanup_cmd, shell=True, capture_output=True, timeout=10)
        return f"⏱️ Command timed out after {timeout} seconds"
    except Exception as e:
        logger.error(f"Error running command: {e}")
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

def categorize_tool_fast(tool_name: str, category_keywords: dict) -> str:
    """Fast tool categorization based on name matching"""
    tool_lower = tool_name.lower()
    for category, keywords in category_keywords.items():
        if any(keyword in tool_lower for keyword in keywords):
            return category
    return None  # Not categorized

def process_binary_batch(binaries: list, category_keywords: dict, start_idx: int, batch_size: int) -> tuple:
    """Process a batch of binaries in parallel - returns (tools_dict, categories_dict)"""
    tools = {}
    categories = {cat: [] for cat in category_keywords.keys()}
    
    end_idx = min(start_idx + batch_size, len(binaries))
    batch = binaries[start_idx:end_idx]
    
    for binary in batch:
        if not binary.strip():
            continue
            
        tool_name = binary.split('/')[-1]
        category = categorize_tool_fast(tool_name, category_keywords)
        
        if category:
            tools[tool_name] = category
            categories[category].append(tool_name)
    
    return tools, categories

def discover_kali_tools_optimized(force_refresh: bool = False) -> dict:
    """
    OPTIMIZED: Parallel tool discovery with progress logging
    """
    global LAST_DISCOVERY_TIME, AVAILABLE_TOOLS, TOOL_CATEGORIES, DISCOVERY_INFO, TOOL_METADATA
    
    current_time = time.time()
    
    # Check caches first
    if not force_refresh:
        if (current_time - LAST_DISCOVERY_TIME) < DISCOVERY_CACHE_TTL and AVAILABLE_TOOLS:
            logger.info("📦 Using in-memory cache")
            return {
                "tools": AVAILABLE_TOOLS,
                "categories": TOOL_CATEGORIES,
                "discovery_info": DISCOVERY_INFO,
                "metadata": TOOL_METADATA
            }
        
        cached = load_cached_tools()
        if cached:
            with discovery_lock:
                AVAILABLE_TOOLS = cached.get("tools", {})
                TOOL_CATEGORIES = cached.get("categories", {})
                DISCOVERY_INFO = cached.get("discovery_info", {})
                TOOL_METADATA = cached.get("metadata", {})
                LAST_DISCOVERY_TIME = current_time
            return cached
    
    logger.info("🔍 Starting OPTIMIZED tool discovery...")
    start_time = time.time()
    
    try:
        # Step 1: Quick filesystem scan (parallelized)
        logger.info("📂 Scanning filesystem for binaries...")
        
        # Use faster find command with parallel execution
        get_bins_cmd = "find /usr/bin /usr/sbin /usr/local/bin -type f -executable 2>/dev/null | sort"
        result = subprocess.run(get_bins_cmd, shell=True, capture_output=True, text=True, timeout=60)
        binaries = [b for b in result.stdout.strip().split('\n') if b.strip()]
        
        logger.info(f"📊 Found {len(binaries)} executable binaries")
        
        # Define category keywords
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
            "Reporting Tools": ["report", "dradis", "cutycapt", "evidence", "faraday", "keimpx"],
            "Post Exploitation": ["priv", "escalat", "persist", "maintain", "lateral", "pivot", "tunnel", "peass", "linpeas", "winpeas"],
        }
        
        # Step 2: Parallel categorization using ThreadPoolExecutor
        logger.info(f"⚡ Processing with {MAX_WORKERS} parallel workers...")
        
        tools = {}
        categories = {cat: [] for cat in category_keywords.keys()}
        
        batch_size = max(100, len(binaries) // MAX_WORKERS)
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for i in range(0, len(binaries), batch_size):
                future = executor.submit(process_binary_batch, binaries, category_keywords, i, batch_size)
                futures.append(future)
            
            # Process results as they complete with progress logging
            completed = 0
            for future in as_completed(futures):
                batch_tools, batch_categories = future.result()
                
                # Merge results (thread-safe)
                with discovery_lock:
                    tools.update(batch_tools)
                    for cat, tool_list in batch_categories.items():
                        categories[cat].extend(tool_list)
                
                completed += 1
                progress = (completed / len(futures)) * 100
                logger.info(f"📈 Progress: {progress:.1f}% ({len(tools)} tools categorized)")
        
        # Remove empty categories
        categories = {k: v for k, v in categories.items() if v}
        
        elapsed = time.time() - start_time
        logger.info(f"✅ Discovery completed in {elapsed:.2f}s")
        logger.info(f"📊 Categorized {len(tools)} tools into {len(categories)} categories")
        
        # Discovery info
        discovery_info = {
            "binaries_found": len(binaries),
            "tools_categorized": len(tools),
            "categories": len(categories),
            "discovery_time_seconds": elapsed,
            "parallel_workers": MAX_WORKERS
        }
        
        # Update global cache
        with discovery_lock:
            AVAILABLE_TOOLS = tools
            TOOL_CATEGORIES = categories
            DISCOVERY_INFO = discovery_info
            TOOL_METADATA = {}  # Metadata extracted on-demand only
            LAST_DISCOVERY_TIME = current_time
        
        # Save to persistent cache
        result = {
            "tools": tools,
            "categories": categories,
            "discovery_info": discovery_info,
            "metadata": {}
        }
        save_cached_tools(result)
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Error discovering tools: {e}", exc_info=True)
        return {"tools": {}, "categories": {}, "discovery_info": {}}

def initialize_tools():
    """Initialize available tools on startup"""
    global AVAILABLE_TOOLS, TOOL_CATEGORIES, DISCOVERY_INFO
    discovery_result = discover_kali_tools_optimized()
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
            help_command = f"{tool_name} --help 2>&1 || {tool_name} -h 2>&1 || {tool_name} 2>&1"
            return run_in_fresh_container(tool_name, help_command, timeout=30)
        
        sanitized_args = sanitize_input(command_args)
        if not sanitized_args:
            return f"❌ Error: Invalid command arguments"
        
        full_command = f"{tool_name} {sanitized_args}"
        
        if not is_safe_command(full_command):
            return "❌ Error: Command contains potentially dangerous operations"
        
        timeout = TARGET_TIMEOUT
        if category in ["Exploitation Tools", "Password Attacks"]:
            timeout = 300
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
                for tool in sorted(tools_list)[:10]:
                    output += f"  - `{tool}`\n"
                if len(tools_list) > 10:
                    output += f"  - ... and {len(tools_list) - 10} more tools\n"
                output += "\n"
    
    output += "\n💡 **Usage:** Execute any tool by calling its name"
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
{sanitized_tool} --help
```

⚠️ **Legal:** Educational use only."""
    
    return info

@mcp.tool()
async def container_status() -> str:
    """Check status of Kali MCP containers and Docker setup."""
    try:
        ps_cmd = f"docker ps --filter name={CONTAINER_PREFIX} --format 'table {{{{.Names}}}}\\t{{{{.Status}}}}'"
        result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
        
        output = "🐳 **Container Status:**\n\n"
        
        if result.returncode == 0 and result.stdout.strip():
            output += result.stdout
        else:
            output += "No Kali MCP containers currently running.\n"
        
        output += f"\n**Configuration:**\n"
        output += f"- Discovered Tools: {len(AVAILABLE_TOOLS)}\n"
        output += f"- Categories: {len(TOOL_CATEGORIES)}\n"
        
        if DISCOVERY_INFO:
            output += f"\n**Discovery Performance:**\n"
            output += f"- Time: {DISCOVERY_INFO.get('discovery_time_seconds', 'N/A')}s\n"
            output += f"- Workers: {DISCOVERY_INFO.get('parallel_workers', 'N/A')}\n"
        
        return output
    except Exception as e:
        return f"❌ Error: {str(e)}"

@mcp.tool()
async def refresh_tool_discovery() -> str:
    """Force refresh of tool discovery."""
    logger.info("🔄 Forcing tool discovery refresh...")
    
    try:
        invalidate_cache()
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
        for tool_name, category in sorted(matches):
            output += f"  - `{tool_name}` ({category})\n"
    else:
        output += "No tools found.\n"
    
    return output

# === DYNAMIC TOOL REGISTRATION ===
def register_dynamic_tools():
    """Dynamically register all discovered tools as MCP tools"""
    logger.info("🚀 Registering dynamic tools...")
    start_time = time.time()
    
    initialize_tools()
    
    skip_tools = {"python3", "python", "bash", "sh", "rm", "chmod"}
    registered = 0
    
    for tool_name, category in AVAILABLE_TOOLS.items():
        if tool_name in skip_tools:
            continue
        
        tool_func = create_tool_function(tool_name, category)
        mcp.tool()(tool_func)
        registered += 1
    
    elapsed = time.time() - start_time
    logger.info(f"✅ Registered {registered} tools in {elapsed:.2f}s")

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("🚀 Starting OPTIMIZED Kali Linux MCP Server...")
    logger.warning("⚠️ Educational purposes only!")
    
    register_dynamic_tools()
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"❌ Server error: {e}", exc_info=True)
        sys.exit(1)
