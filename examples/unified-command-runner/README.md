# 🚀 Unified Command Runner MCP Server

A single MCP server that consolidates multiple command tools into one unified interface, solving the 128-tool limit in MCP.

## 🎯 Problem Solved

Instead of creating individual tools for each command (which quickly exceeds the 128-tool limit), this server provides:
- **1 main tool**: `run_command()` 
- **3 supporting tools**: `list_commands()`, `get_command_info()`, `add_command()`
- **Unlimited commands**: All commands are defined in a configuration dictionary

## 📋 Features

### ✅ **Consolidated Tool Count**
- Only 4 MCP tools total
- Supports unlimited command definitions
- Easy to add new commands without tool count impact

### ✅ **Command Categories**
- **Dice Games**: flip_coin, roll_dice, roll_custom, roll_stats, roll_advantage, roll_disadvantage, roll_check, roll_initiative
- **Security Tools**: nmap, nikto, sqlmap, whois, ping (with Docker container isolation)
- **Extensible**: Add new categories and commands easily

### ✅ **Security**
- Input sanitization for security commands
- Docker container isolation for security tools
- Safe command filtering
- Timeout protection

### ✅ **Dynamic Command Management**
- List all available commands
- Get detailed command information
- Add new commands at runtime
- Category-based filtering

## 🚀 Quick Start

### 1. Build the Docker Image
```bash
cd examples/unified-command-runner
docker build -t unified-command-mcp-server .
```

### 2. Run with Docker MCP Gateway
```bash
# Add to your MCP catalog
docker mcp catalog add unified-command-runner \
  --image unified-command-mcp-server:latest \
  --name "Unified Command Runner"

# Start the gateway
docker mcp gateway run
```

### 3. Use in Your AI Client

#### List all commands:
```
list_commands()
```

#### Get command info:
```
get_command_info(command_name='roll_dice')
```

#### Execute commands:
```
# Dice rolling
run_command(command_name='roll_dice', notation='2d6+3')
run_command(command_name='flip_coin', count='5')

# Security tools
run_command(command_name='nmap', args='-sV -p 80,443 example.com')
run_command(command_name='whois', args='google.com')
```

## 🔧 Command Structure

Each command is defined with:

```python
"command_name": {
    "description": "Human-readable description",
    "category": "dice|security|custom",
    "parameters": {
        "param_name": {
            "type": "string|int|bool",
            "default": "default_value",
            "description": "Parameter description"
        }
    },
    "handler": "function_name_to_handle_command"
}
```

## 📊 Tool Count Comparison

| Approach | Tools Used | Commands Supported |
|----------|------------|-------------------|
| Individual Tools | 128+ | Limited to 128 |
| **Unified Runner** | **4** | **Unlimited** |

## 🎲 Dice Commands Included

- `flip_coin` - Flip coins with probability
- `roll_dice` - Standard dice notation (2d6+3)
- `roll_custom` - Custom dice sides
- `roll_stats` - D&D 4d6 drop lowest
- `roll_advantage` - D20 advantage rolls
- `roll_disadvantage` - D20 disadvantage rolls
- `roll_check` - Skill checks vs DC
- `roll_initiative` - Combat initiative

## 🔒 Security Commands Included

- `nmap` - Network scanning
- `nikto` - Web server scanning  
- `sqlmap` - SQL injection testing
- `whois` - Domain information
- `ping` - Network connectivity

## ➕ Adding New Commands

### Method 1: Code Definition
Add to `COMMAND_DEFINITIONS` in `unified_server.py`:

```python
"my_command": {
    "description": "My custom command",
    "category": "custom",
    "parameters": {
        "input": {"type": "string", "default": "", "description": "Input parameter"}
    },
    "handler": "handle_custom_command"
}
```

### Method 2: Runtime Addition
```python
add_command(
    command_name='my_command',
    description='My custom command', 
    category='custom',
    handler='handle_custom_command',
    parameters='{"input": {"type": "string", "default": "", "description": "Input"}}'
)
```

## 🛡️ Security Features

- **Container Isolation**: Security commands run in isolated Docker containers
- **Input Sanitization**: Removes dangerous characters
- **Command Filtering**: Blocks dangerous operations
- **Timeout Protection**: Prevents long-running commands
- **Non-root User**: Server runs as non-privileged user

## 📝 Example Usage

### D&D Gaming Session
```
# Character creation
run_command(command_name='roll_stats')

# Skill check
run_command(command_name='roll_check', dc='15', modifier='3', skill_name='Perception')

# Combat
run_command(command_name='roll_initiative', modifier='2', combatants='4')
run_command(command_name='roll_advantage', modifier='5')
```

### Security Assessment
```
# Network reconnaissance
run_command(command_name='nmap', args='-sS -O target.com')
run_command(command_name='whois', args='target.com')

# Web scanning
run_command(command_name='nikto', args='-h http://target.com')
```

## 🔄 Migration from Individual Tools

To replace individual MCP tools:

1. **Identify commands** you want to consolidate
2. **Add command definitions** to `COMMAND_DEFINITIONS`
3. **Create handler functions** for each category
4. **Update your MCP catalog** to use the unified server
5. **Remove old individual servers** to free up tool slots

## 🎯 Benefits

- ✅ **Solves 128-tool limit**
- ✅ **Centralized command management**
- ✅ **Consistent interface**
- ✅ **Easy to extend**
- ✅ **Better security isolation**
- ✅ **Reduced resource usage**
- ✅ **Simplified deployment**

## 📚 Documentation

- See `unified_server.py` for implementation details
- Check command definitions for available parameters
- Use `list_commands()` and `get_command_info()` for runtime discovery

---

**Remember**: This approach gives you unlimited command support while using only 4 MCP tools! 🚀