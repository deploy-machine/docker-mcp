# 🔧 UNIFIED Kali Linux MCP Server - Tool Limit Fix

## 🎯 Problem Solved

The original Kali Linux MCP server was automatically discovering 900+ security tools and creating individual MCP tools for each one, **exceeding the 128-tool limit**.

## ✅ Solution Applied

**Modified the server to use only 4 MCP tools total:**

1. `run_security_tool()` - Execute any security tool by name
2. `list_security_tools()` - List all available tools  
3. `get_tool_info()` - Get detailed tool information
4. `container_status()` - Check container status
5. `refresh_tool_discovery()` - Force tool discovery refresh
6. `search_tools()` - Search tools by keyword

## 📊 Tool Count Comparison

| Version | MCP Tools | Security Tools Supported |
|---------|-----------|--------------------------|
| **Original** | **900+** | 900+ |
| **Unified** | **6** | **900+** |

## 🚀 Usage

### Before (Individual Tools):
```bash
nmap(args="-sV target.com")
nikto(args="-h target.com") 
sqlmap(args="-u target.com")
# ... 900+ more individual tools
```

### After (Unified Tool):
```bash
run_security_tool(tool_name="nmap", args="-sV target.com")
run_security_tool(tool_name="nikto", args="-h target.com")
run_security_tool(tool_name="sqlmap", args="-u target.com")
# Same 900+ tools, but using single unified interface
```

## 🔧 Key Changes Made

### 1. Removed Dynamic Tool Registration
- **Removed**: `register_dynamic_tools()` function
- **Removed**: `create_tool_function()` function  
- **Removed**: Individual MCP tool creation for each discovered tool

### 2. Added Unified Tool
- **Added**: `run_security_tool(tool_name, args, help_flag)` 
- **Purpose**: Execute any discovered security tool by name
- **Benefits**: Single tool interface for unlimited commands

### 3. Kept Supporting Tools
- **Maintained**: All discovery and categorization logic
- **Maintained**: Security features (container isolation, input sanitization)
- **Maintained**: Tool information and search capabilities

## 🎮 How It Works

1. **Discovery**: Server still discovers 900+ tools on startup
2. **Categorization**: Tools are still categorized by function
3. **Storage**: Tool information stored in `AVAILABLE_TOOLS` dictionary
4. **Execution**: Single `run_security_tool()` function routes to correct tool
5. **Security**: Same container isolation and input sanitization

## 📋 Available Commands

### List All Tools:
```bash
list_security_tools()
```

### List by Category:
```bash
list_security_tools(category="Information Gathering")
list_security_tools(category="Web Application Analysis")
```

### Get Tool Info:
```bash
get_tool_info(tool_name="nmap")
```

### Execute Tools:
```bash
# Get help
run_security_tool(tool_name="nmap", help_flag="--help")

# Execute with arguments
run_security_tool(tool_name="nmap", args="-sV -p 80,443 target.com")

# Web scanning
run_security_tool(tool_name="nikto", args="-h http://target.com")

# SQL injection testing
run_security_tool(tool_name="sqlmap", args="-u http://target.com/login.php")
```

### Search Tools:
```bash
search_tools(keyword="scan")
search_tools(keyword="sql")
```

## 🛡️ Security Maintained

- ✅ **Container Isolation**: Each command runs in isolated Docker container
- ✅ **Input Sanitization**: Dangerous characters removed
- ✅ **Command Filtering**: Dangerous operations blocked  
- ✅ **Timeout Protection**: Prevents long-running commands
- ✅ **Category-based Timeouts**: Different timeouts for different tool types

## 🔄 Migration Guide

### For Existing Users:
1. **No changes needed** to your Docker setup
2. **Update your AI prompts** to use `run_security_tool(tool_name="...", args="...")` format
3. **Same functionality** - all 900+ tools still available

### Example Prompt Updates:
```diff
- nmap("-sV target.com")
+ run_security_tool(tool_name="nmap", args="-sV target.com")

- nikto("-h target.com")  
+ run_security_tool(tool_name="nikto", args="-h target.com")

- sqlmap("-u target.com")
+ run_security_tool(tool_name="sqlmap", args="-u target.com")
```

## 🎯 Benefits

- ✅ **Fixes 128-tool limit** - Only 6 MCP tools instead of 900+
- ✅ **Same functionality** - All security tools still available
- ✅ **Better performance** - Faster startup, less memory usage
- ✅ **Easier management** - Single interface for all tools
- ✅ **Future-proof** - Can add unlimited tools without hitting limit

## 📝 Technical Details

### Tool Discovery Process (Unchanged):
1. Scan `/usr/bin`, `/usr/sbin`, `/usr/local/bin` for executables
2. Categorize tools using keyword matching
3. Cache results for performance
4. Store in `AVAILABLE_TOOLS` dictionary

### Execution Process (New):
1. User calls `run_security_tool(tool_name="nmap", args="...")`
2. Function validates tool exists in `AVAILABLE_TOOLS`
3. Gets category for timeout determination
4. Sanitizes input arguments
5. Creates fresh Docker container
6. Executes command in container
7. Returns formatted output
8. Cleans up container

## 🚀 Build & Run

```bash
# Build the image
cd examples/kali-linux
docker build -t kali-security-mcp-server:latest .

# Add to MCP catalog
docker mcp catalog add kali-linux-unified \
  --image kali-security-mcp-server:latest \
  --name "Kali Linux Security (Unified)"

# Start gateway
docker mcp gateway run
```

---

**Result**: All 900+ Kali Linux security tools now accessible through just 6 MCP tools, solving the 128-tool limit! 🎉