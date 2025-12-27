#!/usr/bin/env python3
"""
Unified Command Runner MCP Server - Consolidates multiple command tools into a single tool
Solves the 128-tool limit by using a generic command runner with command definitions
"""
import os
import sys
import logging
import subprocess
import json
import time
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("unified-command-server")

# Initialize MCP server
mcp = FastMCP("unified-command-runner")

# Command definitions - maps command names to their configurations
COMMAND_DEFINITIONS = {
    # Dice rolling commands
    "flip_coin": {
        "description": "Flip one or more coins and show results as heads or tails",
        "category": "dice",
        "parameters": {
            "count": {"type": "string", "default": "1", "description": "Number of coins to flip"}
        },
        "handler": "handle_dice_command"
    },
    "roll_dice": {
        "description": "Roll dice using standard notation like 1d20, 2d6+3, 3d8-2",
        "category": "dice", 
        "parameters": {
            "notation": {"type": "string", "default": "1d20", "description": "Dice notation (e.g., 2d6+3)"}
        },
        "handler": "handle_dice_command"
    },
    "roll_custom": {
        "description": "Roll custom dice with any number of sides",
        "category": "dice",
        "parameters": {
            "sides": {"type": "string", "default": "6", "description": "Number of sides on dice"},
            "count": {"type": "string", "default": "1", "description": "Number of dice to roll"}
        },
        "handler": "handle_dice_command"
    },
    "roll_stats": {
        "description": "Roll D&D ability scores using 4d6 drop lowest method",
        "category": "dice",
        "parameters": {},
        "handler": "handle_dice_command"
    },
    "roll_advantage": {
        "description": "Roll a d20 with advantage (roll twice, take higher)",
        "category": "dice",
        "parameters": {
            "modifier": {"type": "string", "default": "0", "description": "Optional modifier"}
        },
        "handler": "handle_dice_command"
    },
    "roll_disadvantage": {
        "description": "Roll a d20 with disadvantage (roll twice, take lower)",
        "category": "dice",
        "parameters": {
            "modifier": {"type": "string", "default": "0", "description": "Optional modifier"}
        },
        "handler": "handle_dice_command"
    },
    "roll_check": {
        "description": "Make a skill check against a DC with a d20 roll plus modifier",
        "category": "dice",
        "parameters": {
            "dc": {"type": "string", "default": "15", "description": "Difficulty class"},
            "modifier": {"type": "string", "default": "0", "description": "Skill modifier"},
            "skill_name": {"type": "string", "default": "", "description": "Name of skill being checked"}
        },
        "handler": "handle_dice_command"
    },
    "roll_initiative": {
        "description": "Roll initiative for one or more combatants in D&D combat",
        "category": "dice",
        "parameters": {
            "modifier": {"type": "string", "default": "0", "description": "Initiative modifier"},
            "combatants": {"type": "string", "default": "1", "description": "Number of combatants"}
        },
        "handler": "handle_dice_command"
    },
    
    # Kali Linux security commands (examples - add more as needed)
    "nmap": {
        "description": "Network discovery and security auditing tool",
        "category": "security",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Nmap arguments (use --help for usage)"}
        },
        "handler": "handle_security_command"
    },
    "nikto": {
        "description": "Web server scanner",
        "category": "security",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Nikto arguments (use --help for usage)"}
        },
        "handler": "handle_security_command"
    },
    "sqlmap": {
        "description": "SQL injection and database takeover tool",
        "category": "security",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "SQLMap arguments (use --help for usage)"}
        },
        "handler": "handle_security_command"
    },
    "whois": {
        "description": "Domain information lookup",
        "category": "security",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Whois arguments (use --help for usage)"}
        },
        "handler": "handle_security_command"
    },
    "ping": {
        "description": "Network ping tool",
        "category": "security",
        "parameters": {
            "args": {"type": "string", "default": "--help", "description": "Ping arguments (use --help for usage)"}
        },
        "handler": "handle_security_command"
    }
}

# Configuration
SECURITY_TIMEOUT = int(os.environ.get("SECURITY_COMMAND_TIMEOUT", "120"))
CONTAINER_PREFIX = os.environ.get("SECURITY_CONTAINER_PREFIX", "unified-mcp")
KALI_BASE_IMAGE = os.environ.get("KALI_BASE_IMAGE", "kali-security-mcp-server:latest")

# Import dice rolling logic (simplified versions)
import random

def parse_dice_notation(notation):
    """Parse dice notation like 2d6+3 into components"""
    try:
        modifier = 0
        if '+' in notation:
            parts = notation.split('+')
            notation = parts[0]
            modifier = int(parts[1])
        elif '-' in notation:
            parts = notation.split('-')
            notation = parts[0]
            modifier = -int(parts[1])
        
        if 'd' in notation.lower():
            parts = notation.lower().split('d')
            num_dice = int(parts[0]) if parts[0] else 1
            sides = int(parts[1])
            return num_dice, sides, modifier
        else:
            return 1, int(notation), modifier
    except:
        return 0, 0, 0

def format_roll_result(rolls, total, modifier=0):
    """Format roll results nicely"""
    if len(rolls) == 1 and modifier == 0:
        return f"🎲 Rolled: {rolls[0]}"
    
    rolls_str = " + ".join(str(r) for r in rolls)
    if modifier > 0:
        return f"🎲 Rolled: {rolls_str} + {modifier} = **{total}**"
    elif modifier < 0:
        return f"🎲 Rolled: {rolls_str} - {abs(modifier)} = **{total}**"
    else:
        return f"🎲 Rolled: {rolls_str} = **{total}**"

# === COMMAND HANDLERS ===

def handle_dice_command(command_name: str, args: dict) -> str:
    """Handle dice rolling commands"""
    try:
        if command_name == "flip_coin":
            count = int(args.get("count", "1"))
            if count < 1 or count > 100:
                return "❌ Error: Must flip between 1 and 100 coins"
            
            results = []
            for _ in range(count):
                results.append("Heads" if random.randint(0, 1) == 1 else "Tails")
            
            if count == 1:
                return f"🪙 Coin flip: **{results[0]}**"
            else:
                heads = results.count("Heads")
                tails = results.count("Tails")
                return f"""🪙 Flipped {count} coins:
- Heads: {heads} ({heads/count*100:.1f}%)
- Tails: {tails} ({tails/count*100:.1f}%)
Results: {', '.join(results)}"""
        
        elif command_name == "roll_dice":
            notation = args.get("notation", "1d20")
            num_dice, sides, modifier = parse_dice_notation(notation)
            if num_dice == 0 and sides == 0 and modifier == 0:
                return f"❌ Error: Invalid dice notation '{notation}'"
            
            if num_dice < 1 or num_dice > 100:
                return "❌ Error: Number of dice must be between 1 and 100"
            if sides < 2 or sides > 1000:
                return "❌ Error: Dice sides must be between 2 and 1000"
            
            rolls = [random.randint(1, sides) for _ in range(num_dice)]
            total = sum(rolls) + modifier
            return format_roll_result(rolls, total, modifier)
        
        elif command_name == "roll_custom":
            sides = int(args.get("sides", "6"))
            count = int(args.get("count", "1"))
            
            if count < 1 or count > 100:
                return "❌ Error: Number of dice must be between 1 and 100"
            if sides < 2 or sides > 1000:
                return "❌ Error: Dice sides must be between 2 and 1000"
            
            rolls = [random.randint(1, sides) for _ in range(count)]
            total = sum(rolls)
            
            result = f"🎲 Rolling {count}d{sides}: "
            if count == 1:
                result += f"**{rolls[0]}**"
            else:
                result += f"{' + '.join(str(r) for r in rolls)} = **{total}**"
            return result
        
        elif command_name == "roll_stats":
            stats = []
            details = []
            
            for i in range(6):
                rolls = sorted([random.randint(1, 6) for _ in range(4)], reverse=True)
                kept = rolls[:3]
                dropped = rolls[3]
                stat_total = sum(kept)
                stats.append(stat_total)
                details.append(f"  {i+1}. Rolled: {rolls} → Kept {kept} (dropped {dropped}) = **{stat_total}**")
            
            stats_sorted = sorted(stats, reverse=True)
            total = sum(stats)
            modifier_total = sum((stat - 10) // 2 for stat in stats)
            
            return f"""⚔️ **D&D Ability Scores** (4d6 drop lowest):

{chr(10).join(details)}

**Final Stats:** {', '.join(str(s) for s in stats)}
**Sorted:** {', '.join(str(s) for s in stats_sorted)}
**Total:** {total} | **Modifier Sum:** {'+' if modifier_total >= 0 else ''}{modifier_total}"""
        
        elif command_name == "roll_advantage":
            modifier = int(args.get("modifier", "0"))
            roll1 = random.randint(1, 20)
            roll2 = random.randint(1, 20)
            higher = max(roll1, roll2)
            total = higher + modifier
            
            result = f"🎯 **Advantage Roll:**\n"
            result += f"  First roll: {roll1}\n"
            result += f"  Second roll: {roll2}\n"
            result += f"  Taking higher: **{higher}**"
            
            if modifier != 0:
                result += f"\n  With modifier: {higher} {'+' if modifier >= 0 else '-'} {abs(modifier)} = **{total}**"
            
            if roll1 == 20 or roll2 == 20:
                result += "\n  🌟 **CRITICAL SUCCESS!**"
            elif roll1 == 1 and roll2 == 1:
                result += "\n  💀 **CRITICAL FAILURE!**"
            
            return result
        
        elif command_name == "roll_disadvantage":
            modifier = int(args.get("modifier", "0"))
            roll1 = random.randint(1, 20)
            roll2 = random.randint(1, 20)
            lower = min(roll1, roll2)
            total = lower + modifier
            
            result = f"😰 **Disadvantage Roll:**\n"
            result += f"  First roll: {roll1}\n"
            result += f"  Second roll: {roll2}\n"
            result += f"  Taking lower: **{lower}**"
            
            if modifier != 0:
                result += f"\n  With modifier: {lower} {'+' if modifier >= 0 else '-'} {abs(modifier)} = **{total}**"
            
            if lower == 20:
                result += "\n  🌟 **CRITICAL SUCCESS!**"
            elif lower == 1:
                result += "\n  💀 **CRITICAL FAILURE!**"
            
            return result
        
        elif command_name == "roll_check":
            dc = int(args.get("dc", "15"))
            modifier = int(args.get("modifier", "0"))
            skill_name = args.get("skill_name", "Check")
            
            roll = random.randint(1, 20)
            total = roll + modifier
            success = total >= dc
            
            result = f"🎲 **{skill_name} (DC {dc}):**\n"
            result += f"  Rolled: {roll}"
            
            if modifier != 0:
                result += f" {'+' if modifier >= 0 else '-'} {abs(modifier)} = **{total}**"
            else:
                result += f" = **{total}**"
            
            if roll == 20:
                result += "\n  🌟 **NATURAL 20! CRITICAL SUCCESS!**"
            elif roll == 1:
                result += "\n  💀 **NATURAL 1! CRITICAL FAILURE!**"
            elif success:
                margin = total - dc
                result += f"\n  ✅ **SUCCESS!** (by {margin} point{'s' if margin != 1 else ''})"
            else:
                margin = dc - total
                result += f"\n  ❌ **FAILURE** (missed by {margin} point{'s' if margin != 1 else ''})"
            
            return result
        
        elif command_name == "roll_initiative":
            modifier = int(args.get("modifier", "0"))
            combatants = int(args.get("combatants", "1"))
            
            if combatants < 1 or combatants > 20:
                return "❌ Error: Number of combatants must be between 1 and 20"
            
            results = []
            for i in range(combatants):
                roll = random.randint(1, 20)
                total = roll + modifier
                results.append((i + 1, roll, total))
            
            results.sort(key=lambda x: x[2], reverse=True)
            
            output = "⚔️ **Initiative Order:**\n"
            for combatant, roll, total in results:
                if combatants == 1:
                    output += f"  Rolled: {roll}"
                    if modifier != 0:
                        output += f" {'+' if modifier >= 0 else '-'} {abs(modifier)}"
                    output += f" = **{total}**"
                else:
                    output += f"  Combatant {combatant}: {roll}"
                    if modifier != 0:
                        output += f" {'+' if modifier >= 0 else '-'} {abs(modifier)}"
                    output += f" = **{total}**\n"
            
            return output.rstrip()
        
        else:
            return f"❌ Error: Unknown dice command '{command_name}'"
    
    except Exception as e:
        logger.error(f"Error in dice command {command_name}: {e}")
        return f"❌ Error: {str(e)}"

def sanitize_input(input_str: str) -> str:
    """Sanitize input to prevent command injection"""
    if not input_str or not input_str.strip():
        return ""
    cleaned = input_str.strip()
    # Remove dangerous characters
    dangerous = ';|`$()<>'
    for char in dangerous:
        cleaned = cleaned.replace(char, '')
    return cleaned

def is_safe_command(command: str) -> bool:
    """Check if command is safe to execute"""
    dangerous_patterns = [
        r'rm\s+/', r'chmod\s+777', r'sudo\s+su', r'passwd',
        r'useradd', r'userdel', r'>\s*/dev/', r'format', r'fdisk', r'mkfs'
    ]
    import re
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

def handle_security_command(command_name: str, args: dict) -> str:
    """Handle security commands"""
    try:
        command_args = args.get("args", "--help")
        return run_security_command_in_container(command_name, command_args, SECURITY_TIMEOUT)
    except Exception as e:
        logger.error(f"Error in security command {command_name}: {e}")
        return f"❌ Error: {str(e)}"

# === MAIN MCP TOOL ===

@mcp.tool()
async def run_command(command_name: str, **kwargs) -> str:
    """
    Execute a command by name. This unified tool replaces multiple individual command tools.
    
    Available commands:
    - Dice games: flip_coin, roll_dice, roll_custom, roll_stats, roll_advantage, roll_disadvantage, roll_check, roll_initiative
    - Security tools: nmap, nikto, sqlmap, whois, ping
    
    Use list_commands() to see all available commands and their parameters.
    """
    if not command_name.strip():
        return "❌ Error: command_name is required"
    
    command_name = command_name.strip()
    
    if command_name not in COMMAND_DEFINITIONS:
        return f"❌ Error: Unknown command '{command_name}'. Use list_commands() to see available commands."
    
    command_def = COMMAND_DEFINITIONS[command_name]
    handler_name = command_def["handler"]
    
    # Route to appropriate handler
    if handler_name == "handle_dice_command":
        return handle_dice_command(command_name, kwargs)
    elif handler_name == "handle_security_command":
        return handle_security_command(command_name, kwargs)
    else:
        return f"❌ Error: Unknown handler '{handler_name}' for command '{command_name}'"

@mcp.tool()
async def list_commands(category: str = "") -> str:
    """List all available commands, optionally filtered by category."""
    output = f"🚀 **Unified Command Runner - Available Commands:**\n\n"
    
    # Group commands by category
    categories = {}
    for cmd_name, cmd_def in COMMAND_DEFINITIONS.items():
        cat = cmd_def["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((cmd_name, cmd_def))
    
    if category.strip():
        if category in categories:
            output += f"**{category.title()} Commands:**\n"
            for cmd_name, cmd_def in categories[category]:
                output += f"  - `{cmd_name}`: {cmd_def['description']}\n"
                if cmd_def.get("parameters"):
                    output += f"    Parameters: {', '.join(cmd_def['parameters'].keys())}\n"
        else:
            available_cats = list(categories.keys())
            output += f"❌ Category '{category}' not found. Available: {', '.join(available_cats)}\n"
    else:
        for cat, commands in categories.items():
            output += f"**{cat.title()}** ({len(commands)} commands):\n"
            for cmd_name, cmd_def in commands:
                output += f"  - `{cmd_name}`: {cmd_def['description']}\n"
            output += "\n"
    
    output += "\n💡 **Usage:** `run_command(command_name='command', param1='value1', param2='value2')`"
    return output

@mcp.tool()
async def get_command_info(command_name: str = "") -> str:
    """Get detailed information about a specific command."""
    if not command_name.strip():
        return "❌ Error: command_name is required"
    
    command_name = command_name.strip()
    
    if command_name not in COMMAND_DEFINITIONS:
        return f"❌ Error: Command '{command_name}' not found"
    
    cmd_def = COMMAND_DEFINITIONS[command_name]
    
    output = f"📋 **Command Information: {command_name}**\n\n"
    output += f"**Description:** {cmd_def['description']}\n"
    output += f"**Category:** {cmd_def['category']}\n"
    output += f"**Handler:** {cmd_def['handler']}\n"
    
    if cmd_def.get("parameters"):
        output += f"\n**Parameters:**\n"
        for param_name, param_info in cmd_def["parameters"].items():
            output += f"  - `{param_name}` ({param_info.get('type', 'string')}): {param_info.get('description', 'No description')}"
            if 'default' in param_info:
                output += f" [default: {param_info['default']}]"
            output += "\n"
    
    output += f"\n**Example Usage:**\n```\nrun_command(command_name='{command_name}'"
    for param_name, param_info in cmd_def.get("parameters", {}).items():
        if 'default' in param_info:
            output += f", {param_name}='{param_info['default']}'"
    output += ")\n```"
    
    return output

@mcp.tool()
async def add_command(command_name: str, description: str, category: str, handler: str, parameters: str = "{}") -> str:
    """Add a new command definition to the unified runner."""
    try:
        if not command_name.strip():
            return "❌ Error: command_name is required"
        
        command_name = command_name.strip()
        
        if command_name in COMMAND_DEFINITIONS:
            return f"❌ Error: Command '{command_name}' already exists"
        
        # Parse parameters JSON
        try:
            params_dict = json.loads(parameters) if parameters.strip() else {}
        except json.JSONDecodeError as e:
            return f"❌ Error: Invalid parameters JSON: {e}"
        
        # Add command definition
        COMMAND_DEFINITIONS[command_name] = {
            "description": description,
            "category": category,
            "handler": handler,
            "parameters": params_dict
        }
        
        return f"✅ Successfully added command '{command_name}'"
        
    except Exception as e:
        logger.error(f"Error adding command: {e}")
        return f"❌ Error: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("🚀 Starting Unified Command Runner MCP Server...")
    logger.info(f"📊 Loaded {len(COMMAND_DEFINITIONS)} command definitions")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"❌ Server error: {e}", exc_info=True)
        sys.exit(1)