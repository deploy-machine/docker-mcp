#!/bin/bash

# =============================================================================
# Kali Linux Dynamic MCP Server - Automatic Setup Script
# =============================================================================
# This script automates the entire setup process for the Kali Linux MCP server
# =============================================================================

set -e # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

export SKIP_BASE_BUILD=false
export SKIP_READY_BUILD=false
export SKIP_WARMUP=false
export FORCE_REBUILD=false
export CLEAN_SETUP=false
# Configuration variables
KALI_BASE_IMAGE="kalilinux/kali-rolling"
KALI_READY_IMAGE="kali-mcp-ready"
SERVER_NAME="kali-security"
CONTAINER_PREFIX="kali-security"
TARGET_TIMEOUT="120"
HOME_DIR="$HOME"
MCP_DIR="$HOME_DIR/.docker/mcp"
CATALOGS_DIR="$MCP_DIR/catalogs"
REGISTRY_FILE="$MCP_DIR/registry.yaml"
CLAUDE_CONFIG=""
KALI_CATALOG_NAME="kali-security"
KALI_CATALOG_FILE="$CATALOGS_DIR/kali-security.yaml"

parse_arguments() {
  while [[ $# -gt 0 ]]; do
    case $1 in
    --clean)
      CLEAN_SETUP=true
      shift
      ;;
    --force)
      FORCE_REBUILD=true
      shift
      ;;
    --help | -h)
      show_usage
      exit 0
      ;;
    *)
      print_error "Unknown option: $1"
      show_usage
      exit 1
      ;;
    esac
  done
}

cleanup_all() {
  print_status "Performing complete cleanup..."
  echo ""
  print_warning "This will delete:"
  echo "  - Docker images (kali-security-mcp-server, kali-mcp-ready)"
  echo "  - Tool discovery cache"
  echo "  - Catalog files"
  echo "  - Server registrations"
  echo ""
  read -p "Are you sure you want to continue? [y/N] " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_status "Cleanup cancelled"
    return 0
  fi

  # Stop containers
  print_status "Stopping Kali containers..."
  docker stop $(docker ps -a | grep kali-security | awk '{print $1}') 2>/dev/null || true

  # Remove images
  print_status "Removing Docker images..."
  docker rmi kali-security-mcp-server:latest 2>/dev/null || true
  docker rmi kali-mcp-ready:latest 2>/dev/null || true

  # Remove cache
  print_status "Removing tool discovery cache..."
  rm -f "$HOME_DIR/.docker/mcp/kali-tools-cache.json"

  # Remove catalog
  print_status "Removing catalog files..."
  rm -f "$CATALOGS_DIR/kali-security.yaml"

  # Disable server
  print_status "Disabling MCP server..."
  docker mcp server disable kali-security 2>/dev/null || true

  # Clean registry
  print_status "Cleaning registry..."
  sed -i.backup '/kali-security:/,/ref: ""/d' "$REGISTRY_FILE" 2>/dev/null || true

  print_success "Cleanup complete!"
  echo ""
}

check_existing_setup() {
  print_status "Checking existing setup state..."
  # Check base MCP server image
  if docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "kali-security-mcp-server:latest"; then
    print_success "✓ Base image exists: kali-security-mcp-server:latest"
  else
    print_warning "✗ Base image not found"
  fi
  # Check ready image (with tools installed)
  if docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "kali-mcp-ready:latest"; then
    print_success "✓ Ready image exists: kali-mcp-ready:latest"
  else
    print_warning "✗ Ready image not found - will build during warm-up"
  fi
  # Check if tool discovery cache exists
  if [ -f "$HOME_DIR/.docker/mcp/kali-tools-cache.json" ]; then
    print_success "✓ Tool discovery cache found"
  else
    print_warning "✗ Tool discovery cache not found - will discover"
  fi
  # Check if catalog exists
  if docker mcp catalog show "$KALI_CATALOG_NAME" &>/dev/null; then
    print_success "✓ Catalog imported in Docker MCP"
  else
    print_warning "✗ Catalog not imported - will create"
  fi
  # Check if server is enabled
  if docker mcp server ls 2>/dev/null | grep -q "kali-security"; then
    print_success "✓ Server is enabled"
  else
    print_warning "✗ Server not enabled - will enable"
  fi
  echo ""
  return 0
}

show_usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --clean        Delete all existing images, cache, and configs before setup"
  echo "  --force        Force rebuild even if images exist"
  echo "  --help, -h     Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0                  # Normal run (prompts if images exist)"
  echo "  $0 --clean          # Complete clean install"
  echo "  $0 --force          # Force rebuild without prompts"
}

# Function to print colored output
print_status() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect which AI client is being used
detect_client_config() {
  # Check if opencode configuration exists
  if [ -d "$HOME_DIR/.opencode" ] || [ -f "$HOME_DIR/.config/opencode/config.yaml" ]; then
    AI_CLIENT="opencode"
    print_status "Detected opencode client"
  elif [ -d "$HOME_DIR/Library/Application Support/Claude" ] || [ -d "$HOME_DIR/.config/Claude" ]; then
    AI_CLIENT="claude"
    print_status "Detected Claude Desktop client"
  else
    print_warning "No AI client configuration detected, defaulting to Claude Desktop"
    AI_CLIENT="claude"
  fi
}

# Function to detect OS and set config path based on client
detect_config_path() {
  case "$AI_CLIENT" in
  "opencode")
    detect_opencode_config
    ;;
  "claude")
    detect_claude_config
    ;;
  esac
}

detect_claude_config() {
  case "$(uname -s)" in
  Darwin*)
    CLAUDE_CONFIG="$HOME_DIR/Library/Application Support/Claude/claude_desktop_config.json"
    ;;
  Linux*)
    CLAUDE_CONFIG="$HOME_DIR/.config/Claude/claude_desktop_config.json"
    ;;
  CYGWIN* | MINGW* | MSYS*)
    CLAUDE_CONFIG="$APPDATA\\Claude\\claude_desktop_config.json"
    ;;
  *)
    print_error "Unsupported operating system"
    exit 1
    ;;
  esac
}

detect_opencode_config() {
  case "$(uname -s)" in
  Darwin*)
    OPENCODE_CONFIG="$HOME_DIR/Library/Application Support/opencode/config.yaml"
    ;;
  Linux*)
    OPENCODE_CONFIG="$HOME_DIR/.config/opencode/config.yaml"
    ;;
  CYGWIN* | MINGW* | MSYS*)
    OPENCODE_CONFIG="$APPDATA\\opencode\\config.yaml"
    ;;
  *)
    print_error "Unsupported operating system"
    exit 1
    ;;
  esac
}

# Function to check prerequisites
check_prerequisites() {
  print_status "Checking prerequisites..."

  # Check Docker
  if ! command -v docker &>/dev/null; then
    print_error "Docker is not installed or not in PATH"
    print_error "Please install Docker Desktop first: https://www.docker.com/products/docker-desktop/"
    exit 1
  fi

  # Check if Docker daemon is running
  if ! docker info &>/dev/null; then
    print_error "Docker daemon is not running"
    print_error "Please start Docker Desktop"
    exit 1
  fi

  print_success "Docker prerequisites satisfied"
}

check_existing_setup() {
  print_status "Checking existing setup state..."

  local base_exists=false
  local ready_exists=false
  local tools_discovered=false

  # Check base MCP server image
  if docker images | grep -q "kali-security-mcp-server"; then
    print_success "Base image exists: kali-security-mcp-server:latest"
    base_exists=true
  else
    print_warning "Base image not found - will build"
  fi

  # Check ready image (with tools installed)
  if docker images | grep -q "$KALI_READY_IMAGE"; then
    print_success "Ready image exists: $KALI_READY_IMAGE:latest"
    ready_exists=true
  else
    print_warning "Ready image not found - will build during warm-up"
  fi

  # Check if tool discovery cache exists
  if [ -f "$HOME_DIR/.docker/mcp/kali-tools-cache.json" ]; then
    print_success "Tool discovery cache found"
    tools_discovered=true
  else
    print_warning "Tool discovery cache not found - will discover"
  fi

  # Decision matrix
  if [ "$base_exists" = true ] && [ "$ready_exists" = true ] && [ "$tools_discovered" = true ]; then
    print_success "Complete setup already exists!"
    echo ""
    read -p "Skip rebuild and use existing setup? [Y/n] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
      SKIP_BUILD=true
      SKIP_WARMUP=true
      return 0
    fi
  elif [ "$base_exists" = true ] && [ "$ready_exists" = true ]; then
    print_success "Images exist, only tool discovery needed"
    SKIP_BUILD=true
    SKIP_WARMUP=false
  elif [ "$base_exists" = true ]; then
    print_success "Base image exists, will build ready image"
    SKIP_BUILD=true # Skip base build, but do ready build
    SKIP_WARMUP=false
  fi

  return 0
}

# Function to create necessary directories
create_directories() {
  print_status "Creating MCP directories..."

  mkdir -p "$CATALOGS_DIR"
  mkdir -p "$(dirname "$REGISTRY_FILE")"

  print_success "Directories created"
}

# Function to build Docker image
build_docker_image() {
  # Check if base image already exists
  if docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "kali-security-mcp-server:latest"; then
    print_status "Base image already exists - skipping build"
    return 0
  fi

  print_status "Building Kali Linux Security MCP Server image..."
  print_warning "This may take 15-30 minutes on first build"
  cd "$(dirname "$0")"
  if docker build -t "kali-security-mcp-server" .; then
    print_success "Docker image built successfully"
  else
    print_error "Failed to build Docker image"
    exit 1
  fi
}

# Function to set Docker MCP secrets
set_docker_secrets() {
  print_status "Setting Docker MCP secrets..."

  docker mcp secret set KALI_TARGET_TIMEOUT="$TARGET_TIMEOUT" 2>/dev/null || true
  docker mcp secret set KALI_CONTAINER_PREFIX="$CONTAINER_PREFIX" 2>/dev/null || true
  docker mcp secret set KALI_BASE_IMAGE="kali-security-mcp-server:latest" 2>/dev/null || true
  docker mcp secret set KALI_READY_IMAGE="$KALI_READY_IMAGE" 2>/dev/null || true

  print_success "Docker secrets configured"
}

# Function to configure MCP config.yaml for kali-security
configure_mcp_config() {
  print_status "Configuring MCP config.yaml for kali-security..."
  
  local config_file="$MCP_DIR/config.yaml"
  
  # Create config.yaml if it doesn't exist
  if [ ! -f "$config_file" ]; then
    touch "$config_file"
  fi
  
  # Check if kali-security config already exists
  if grep -q "^kali-security:" "$config_file" 2>/dev/null; then
    print_status "kali-security config already exists, updating..."
    # Remove old config section
    sed -i.backup '/^kali-security:/,/^[^ ]/d' "$config_file"
  fi
  
  # Append kali-security configuration
  cat >>"$config_file" <<EOF
kali-security:
  KALI_BASE_IMAGE: "kali-security-mcp-server:latest"
  KALI_CONTAINER_PREFIX: "$CONTAINER_PREFIX"
  KALI_TARGET_TIMEOUT: "$TARGET_TIMEOUT"
  KALI_READY_IMAGE: "$KALI_READY_IMAGE"
EOF
  
  print_success "MCP config.yaml updated with kali-security settings"
}

# Function to warm up tool discovery
warmup_tool_discovery() {
  # Check if ready image and cache already exist - skip if both present
  local ready_exists=false
  local cache_exists=false

  if docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "kali-mcp-ready:latest"; then
    ready_exists=true
  fi

  if [ -f "$HOME_DIR/.docker/mcp/kali-tools-cache.json" ]; then
    cache_exists=true
  fi

  if [ "$ready_exists" = true ] && [ "$cache_exists" = true ]; then
    print_success "Ready image and tool cache already exist - skipping warm-up"
    return 0
  fi

  print_status "Running tool discovery warm-up..."

  if [ "$ready_exists" = true ]; then
    print_success "Ready image already exists, only running tool discovery"
    print_status "This should be fast (~2-3 minutes)"
  else
    print_warning "Ready image not found - will install kali-linux-everything"
    print_warning "This process can take 10-30 minutes depending on your system"
  fi

  print_warning "Please be patient - this makes first-time usage in OpenCode instant!"

  # Start temporary container to run discovery
  local warmup_container="$CONTAINER_PREFIX-warmup-$$"

  print_status "Starting warm-up container..."
  docker run -d \
    --name "$warmup_container" \
    --rm \
    -e KALI_TARGET_TIMEOUT="$TARGET_TIMEOUT" \
    -e KALI_CONTAINER_PREFIX="$CONTAINER_PREFIX" \
    -e KALI_BASE_IMAGE="kali-security-mcp-server:latest" \
    -e KALI_READY_IMAGE="$KALI_READY_IMAGE" \
    -e KALI_SKIP_BUILD="$ready_exists" \
    -e KALI_CACHE_FILE="/mcp/kali-tools-cache.json" \
    -v "$HOME_DIR/.docker/mcp:/mcp" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "kali-security-mcp-server:latest" \
    tail -f /dev/null

  # Wait for container to be ready
  sleep 3

  # Execute warm-up script inside container
  print_status "Executing tool discovery..."
  docker exec "$warmup_container" python -c "
import sys
sys.path.insert(0, '/app')
from kali_server import discover_kali_tools, logger
logger.info('Starting tool discovery warm-up...')
result = discover_kali_tools(force_refresh=True)
logger.info(f'Discovered {len(result[\"tools\"])} tools in {len(result[\"categories\"])} categories')
logger.info('Warm-up complete!')
print(f'WARMUP_COMPLETE:{len(result[\"tools\"])}')
" 2>&1 | tee /tmp/kali-warmup.log &

  local warmup_pid=$!

  # Show progress
  echo ""
  print_status "Discovery in progress (PID: $warmup_pid)..."
  if [ "$ready_exists" = true ]; then
    print_status "Using existing ready image (fast path)"
  else
    print_status "Installing packages and discovering tools (slow path)"
  fi
  echo ""

  # Wait for completion (with extended timeout)
  local timeout=1800 # 30 minutes max
  local elapsed=0
  while kill -0 $warmup_pid 2>/dev/null; do
    if [ $elapsed -ge $timeout ]; then
      print_error "Warm-up timed out after ${timeout}s (30 minutes)"
      docker stop "$warmup_container" 2>/dev/null
      rm -f /tmp/kali-warmup.log
      return 1
    fi

    # Show progress every 30 seconds
    if [ $((elapsed % 30)) -eq 0 ]; then
      printf "\n[${elapsed}s elapsed]"
    fi
    printf "."
    sleep 5
    elapsed=$((elapsed + 5))
  done
  echo ""

  # Check results
  if grep -q "WARMUP_COMPLETE" /tmp/kali-warmup.log; then
    local tool_count=$(grep -o "WARMUP_COMPLETE:[0-9]*" /tmp/kali-warmup.log | cut -d: -f2)
    print_success "Tool discovery complete! Found $tool_count tools"
    print_success "Cache saved to ~/.docker/mcp/kali-tools-cache.json"
    print_success "These will be available immediately when you start OpenCode"
  else
    print_warning "Warm-up completed but results unclear"
    print_warning "Tools will still be discovered on first use"
  fi

  # Cleanup
  print_status "Cleaning up warm-up container..."
  docker stop "$warmup_container" 2>/dev/null || true
  rm -f /tmp/kali-warmup.log
}
# Function to create custom catalog
create_custom_catalog() {
  if docker mcp catalog show "$KALI_CATALOG_NAME" &>/dev/null; then
    print_success "Catalog already imported - skipping"
    return 0
  fi

  print_status "Creating Kali Security MCP catalog..."

  # Create the catalog YAML file
  cat >"$KALI_CATALOG_FILE" <<'EOF'
version: 2
name: kali-security
displayName: Kali Linux Security Tools
registry:
  kali-security:
    description: "Dynamic Kali Linux security server with 600+ tools including nmap, metasploit, nikto, sqlmap, and more. Each tool runs in fresh isolated containers."
    title: "Kali Linux Security Tools"
    type: server
    dateAdded: "2025-12-23T00:00:00Z"
    image: kali-security-mcp-server:latest
    ref: ""
    readme: ""
    toolsUrl: ""
    source: ""
    upstream: ""
    icon: "https://www.kali.org/images/kali-logo.svg"
    tools:
      - name: list_security_tools
        description: "List all 600+ available security tools by category"
      - name: get_tool_info
        description: "Get detailed usage information for any security tool"
      - name: search_tools
        description: "Search for security tools by keyword"
      - name: container_status
        description: "Check status of Kali containers and Docker setup"
      - name: refresh_tool_discovery
        description: "Force refresh tool discovery to find new tools"
      - name: get_tool_metadata
        description: "Get detailed metadata (version, package, size) for a tool"
      - name: install_tool
        description: "Install additional security tools in the Kali image"
    secrets:
      - name: KALI_TARGET_TIMEOUT
        env: KALI_TARGET_TIMEOUT
        example: "120"
      - name: KALI_CONTAINER_PREFIX
        env: KALI_CONTAINER_PREFIX
        example: "kali-security"
      - name: KALI_BASE_IMAGE
        env: KALI_BASE_IMAGE
        example: "kali-security-mcp-server:latest"
      - name: KALI_READY_IMAGE
        env: KALI_READY_IMAGE
        example: "kali-mcp-ready"
    metadata:
      category: security
      tags:
        - security
        - penetration-testing
        - kali-linux
        - nmap
        - metasploit
        - nikto
        - sqlmap
        - burpsuite
        - vulnerability-assessment
        - forensics
        - cybersecurity
      license: MIT
      owner: local
EOF
  print_success "Catalog file created at $KALI_CATALOG_FILE"

  # Import catalog into Docker MCP system
  print_status "Importing catalog into Docker MCP..."
  if docker mcp catalog import "$KALI_CATALOG_FILE"; then
    print_success "Catalog imported successfully"
  else
    print_error "Failed to import catalog"
    print_error "Manual import: docker mcp catalog import $KALI_CATALOG_FILE"
    exit 1
  fi
}

# Function to enable kali security MCP server
enable_server() {
  # Check if server is already enabled
  if docker mcp server ls 2>/dev/null | grep -q "$SERVER_NAME"; then
    print_success "Server already enabled - skipping"
    return 0
  fi

  print_status "Enabling Kali Security MCP server..."

  # Enable the server (this adds it to registry.yaml automatically)
  if docker mcp server enable "$SERVER_NAME"; then
    print_success "Server enabled successfully"
  else
    print_error "Failed to enable server"
    print_error "Manual enable: docker mcp server enable $SERVER_NAME"
    print_error "Check catalog: docker mcp catalog show $KALI_CATALOG_NAME"
    exit 1
  fi

  # Verify it's in the registry
  if grep -q "$SERVER_NAME:" "$REGISTRY_FILE" 2>/dev/null; then
    print_success "Server registered in registry.yaml"
  else
    print_warning "Server may not be in registry.yaml, but Docker MCP tracks it internally"
  fi
}

# Function to update AI client config
update_client_config() {
  case "$AI_CLIENT" in
  "opencode")
    update_opencode_config
    ;;
  "claude")
    update_claude_config
    ;;
  esac
}

update_claude_config() {
  print_status "Updating Claude Desktop configuration..."

  detect_claude_config

  # Create backup of existing config
  if [ -f "$CLAUDE_CONFIG" ]; then
    cp "$CLAUDE_CONFIG" "$CLAUDE_CONFIG.backup.$(date +%s)"
    print_warning "Backup of existing config created"
  fi

  # Get the home directory in the correct format for the OS
  case "$(uname -s)" in
  Darwin*)
    HOME_FOR_CONFIG="$HOME_DIR"
    ;;
  Linux*)
    HOME_FOR_CONFIG="$HOME_DIR"
    ;;
  CYGWIN* | MINGW* | MSYS*)
    HOME_FOR_CONFIG="$(cygpath -w "$HOME_DIR")"
    ;;
  esac

  # Create or update Claude config
  cat >"$CLAUDE_CONFIG" <<EOF
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "$HOME_FOR_CONFIG/.docker/mcp:/mcp",
        "docker/mcp-gateway",
        "--catalog=/mcp/catalogs/docker-mcp.yaml",
        "--catalog=/mcp/catalogs/kali-security.yaml",
        "--config=/mcp/config.yaml",
        "--registry=/mcp/registry.yaml",
        "--tools-config=/mcp/tools.yaml",
        "--transport=stdio"
      ]
    }
  }
}
EOF

  print_success "Claude Desktop configuration updated"
}

update_opencode_config() {
  print_status "Updating opencode configuration..."

  detect_opencode_config

  # Create backup of existing config
  if [ -f "$OPENCODE_CONFIG" ]; then
    cp "$OPENCODE_CONFIG" "$OPENCODE_CONFIG.backup.$(date +%s)"
    print_warning "Backup of existing config created"
  fi

  # Get the home directory in the correct format for the OS
  case "$(uname -s)" in
  Darwin*)
    HOME_FOR_CONFIG="$HOME_DIR"
    ;;
  Linux*)
    HOME_FOR_CONFIG="$HOME_DIR"
    ;;
  CYGWIN* | MINGW* | MSYS*)
    HOME_FOR_CONFIG="$(cygpath -w "$HOME_DIR")"
    ;;
  esac

  # Create or update opencode config
  cat >"$OPENCODE_CONFIG" <<EOF
# opencode configuration
mcp_servers:
  docker-mcp-gateway:
    command: docker
    args:
      - run
      - -i
      - --rm
      - -v
      - /var/run/docker.sock:/var/run/docker.sock
      - -v
      - "$HOME_FOR_CONFIG/.docker/mcp:/mcp"
      - docker/mcp-gateway
      - --catalog=/mcp/catalogs/docker-mcp.yaml
      - --catalog=/mcp/catalogs/kali-security.yaml
      - --config=/mcp/config.yaml
      - --registry=/mcp/registry.yaml
      - --tools-config=/mcp/tools.yaml
      - --transport=stdio
EOF

  print_success "opencode configuration updated"
}

# Function to test the setup
test_setup() {
  print_status "Testing the setup..."

  # Test 1: Docker image
  if docker images | grep -q "kali-security-mcp-server"; then
    print_success "Docker image is available"
  else
    print_error "Docker image not found"
    return 1
  fi

  # Test 2: Catalog file exists
  if [ -f "$KALI_CATALOG_FILE" ]; then
    print_success "Catalog file exists"
  else
    print_error "Catalog file missing"
    return 1
  fi

  # Test 3: Catalog is imported in Docker MCP
  if docker mcp catalog show "$KALI_CATALOG_NAME" &>/dev/null; then
    print_success "Catalog is imported in Docker MCP"
  else
    print_error "Catalog not imported in Docker MCP"
    return 1
  fi

  # Test 4: Server is in catalog
  if docker mcp catalog show "$KALI_CATALOG_NAME" | grep -q "$SERVER_NAME"; then
    print_success "Server is listed in catalog"
  else
    print_error "Server not in catalog"
    return 1
  fi

  # Test 5: Server is enabled
  if docker mcp server ls | grep -q "$SERVER_NAME"; then
    print_success "Server is enabled"
  else
    print_error "Server not enabled"
    return 1
  fi

  # Test 6: Client config includes catalog
  local config_file=""
  case "$AI_CLIENT" in
  "opencode")
    config_file="$OPENCODE_CONFIG"
    ;;
  "claude")
    config_file="$CLAUDE_CONFIG"
    ;;
  esac

  if [ -n "$config_file" ] && [ -f "$config_file" ]; then
    if grep -q "kali-security.yaml" "$config_file"; then
      print_success "$AI_CLIENT config includes Kali catalog"
    else
      print_error "$AI_CLIENT config missing Kali catalog reference"
      return 1
    fi
  fi

  return 0
}

# Function to create systemd service for auto-start
create_systemd_service() {
  if [ "$(uname -s)" != "Linux" ]; then
    return 0
  fi

  print_status "Creating systemd service for auto-start..."

  local service_file="/etc/systemd/system/kali-security-gateway.service"
  local service_content="[Unit]
Description=Kali Security MCP Gateway
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=$USER
Group=docker
ExecStart=/usr/bin/docker run --rm -i \\
    -v /var/run/docker.sock:/var/run/docker.sock \\
    -v $HOME_DIR/.docker/mcp:/mcp \\
    docker/mcp-gateway \\
    --catalog=/mcp/catalogs/docker-mcp.yaml \\
    --catalog=/mcp/catalogs/kali-security.yaml \\
    --config=/mcp/config.yaml \\
    --registry=/mcp/registry.yaml \\
    --tools-config=/mcp/tools.yaml \\
    --transport=stdio
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target"

  # Create service file with sudo
  if echo "$service_content" | sudo tee "$service_file" >/dev/null; then
    print_success "Systemd service created"

    # Enable and start the service
    if sudo systemctl daemon-reload && sudo systemctl enable kali-security-gateway.service; then
      print_success "Service enabled for auto-start on boot"
      print_warning "To start service now: sudo systemctl start kali-security-gateway.service"
      print_warning "To check status: sudo systemctl status kali-security-gateway.service"
    else
      print_error "Failed to enable systemd service"
    fi
  else
    print_warning "Could not create systemd service (requires sudo)"
    print_warning "You can manually create the service or use Docker Desktop auto-start"
  fi
}

# Function to create launchd service for macOS
create_launchd_service() {
  if [ "$(uname -s)" != "Darwin" ]; then
    return 0
  fi

  print_status "Creating launchd service for auto-start..."

  local plist_file="$HOME_DIR/Library/LaunchAgents/com.docker.mcp.kali-security.plist"
  local plist_content="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.docker.mcp.kali-security</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/docker</string>
        <string>run</string>
        <string>--rm</string>
        <string>-i</string>
        <string>-v</string>
        <string>/var/run/docker.sock:/var/run/docker.sock</string>
        <string>-v</string>
        <string>$HOME_DIR/.docker/mcp:/mcp</string>
        <string>docker/mcp-gateway</string>
        <string>--catalog=/mcp/catalogs/docker-mcp.yaml</string>
        <string>--catalog=/mcp/catalogs/kali-security.yaml</string>
        <string>--config=/mcp/config.yaml</string>
        <string>--registry=/mcp/registry.yaml</string>
        <string>--tools-config=/mcp/tools.yaml</string>
        <string>--transport=stdio</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$HOME_DIR/.docker/mcp/kali-security.log</string>
    <key>StandardErrorPath</key>
    <string>$HOME_DIR/.docker/mcp/kali-security.error.log</string>
</dict>
</plist>"

  if echo "$plist_content" >"$plist_file"; then
    print_success "Launchd plist file created"

    # Load the launchd agent
    if launchctl load "$plist_file" 2>/dev/null; then
      print_success "Service loaded for auto-start on login"
      print_warning "To start service now: launchctl start com.docker.mcp.kali-security"
      print_warning "To unload: launchctl unload com.docker.mcp.kali-security"
    else
      print_warning "Service created but not loaded (may require manual loading)"
    fi
  else
    print_error "Failed to create launchd plist file"
  fi
}

# Function to setup Docker Desktop auto-start
setup_docker_autostart() {
  print_status "Configuring Docker Desktop auto-start..."

  case "$(uname -s)" in
  Darwin*)
    # On macOS, Docker Desktop has a setting for auto-start
    print_status "On macOS:"
    echo "  1. Open Docker Desktop"
    echo "  2. Go to Settings → General"
    echo "  3. Enable 'Start Docker Desktop when you log in'"
    echo "  4. Also enable 'Automatically start necessary containers'"
    ;;
  Linux*)
    # On Linux, enable docker service
    if command -v systemctl &>/dev/null; then
      print_status "Enabling Docker service for auto-start..."
      if sudo systemctl enable docker.service 2>/dev/null; then
        print_success "Docker service enabled for auto-start"
      else
        print_warning "Could not enable Docker service (requires sudo)"
      fi
    fi
    ;;
  CYGWIN* | MINGW* | MSYS*)
    # On Windows, Docker Desktop auto-starts by default
    print_status "On Windows, Docker Desktop auto-starts by default"
    ;;
  esac
}

# Function to show next steps
show_next_steps() {
  print_success "Setup completed successfully!"
  echo
  echo -e "${GREEN}=== NEXT STEPS ===${NC}"
  echo
  case "$AI_CLIENT" in
  "opencode")
    echo "1. ${BLUE}Restart opencode${NC}"
    echo "   - Completely quit opencode"
    echo "   - Start opencode again"
    ;;
  "claude")
    echo "1. ${BLUE}Restart Claude Desktop${NC}"
    echo "   - Completely quit Claude Desktop"
    echo "   - Start Claude Desktop again"
    ;;
  esac
  echo
  echo "2. ${BLUE}Verify MCP Gateway Configuration${NC}"
  echo "   - Ensure your MCP client is configured to use Docker MCP Gateway"
  echo "   - Check that custom catalog is included in gateway config"
  echo
  echo "3. ${BLUE}Wait for Tool Discovery${NC}"
  echo "   - First run takes 2-3 minutes for tool discovery"
  echo "   - Large Kali image may need to download (~10GB)"
  echo
  echo "4. ${BLUE}Start Using${NC}"
  echo "   - Ask your AI assistant: 'List all security tools'"
  echo "   - Try: 'nmap --help'"
  echo "   - Try: 'get_tool_info nmap'"
  echo
  echo -e "${GREEN}=== AUTO-START SETUP ===${NC}"
  echo "The script has configured auto-start services:"
  case "$(uname -s)" in
  Darwin*)
    echo "  • Launchd agent created for login auto-start"
    echo "  • Enable Docker Desktop auto-start in settings"
    ;;
  Linux*)
    echo "  • Systemd service created for boot auto-start"
    echo "  • Docker service enabled for auto-start"
    ;;
  CYGWIN* | MINGW* | MSYS*)
    echo "  • Docker Desktop auto-starts by default on Windows"
    ;;
  esac
  echo
  echo -e "${YELLOW}=== IMPORTANT LEGAL NOTICE ===${NC}"
  echo "This server provides access to professional security testing tools."
  echo "ONLY use on systems you own or have explicit permission to test."
  echo "Unauthorized use may be illegal and result in prosecution."
  echo
  echo -e "${GREEN}=== VERIFICATION COMMANDS ===${NC}"
  echo "Check if everything is working:"
  echo "  docker images | grep kali-security-mcp-server"
  echo "  docker mcp catalog show kali-security"
  echo "  docker mcp server ls | grep kali-security"
  echo "  docker ps  # Check running containers when using tools"
  echo
  echo -e "${GREEN}=== AUTO-START MANAGEMENT ===${NC}"
  case "$(uname -s)" in
  Darwin*)
    echo "  • Status: launchctl list | grep com.docker.mcp.kali-security"
    echo "  • Start: launchctl start com.docker.mcp.kali-security"
    echo "  • Stop: launchctl stop com.docker.mcp.kali-security"
    echo "  • Remove: launchctl unload ~/Library/LaunchAgents/com.docker.mcp.kali-security.plist"
    ;;
  Linux*)
    echo "  • Status: sudo systemctl status kali-security-gateway.service"
    echo "  • Start: sudo systemctl start kali-security-gateway.service"
    echo "  • Stop: sudo systemctl stop kali-security-gateway.service"
    echo "  • Remove: sudo systemctl disable kali-security-gateway.service"
    ;;
  esac
  echo "3. ${BLUE}Available Management Tools${NC}"
  echo "   - list_security_tools - Browse 600+ tools by category"
  echo "   - get_tool_info - Get help for specific tools"
  echo "   - search_tools - Find tools by keyword"
  echo "   - refresh_tool_discovery - Force re-scan for tools"
  echo "   - get_tool_metadata - Get version/package details"
  echo "   - install_tool - Install additional tools"
  echo "   - container_status - Check container health"
  echo
  echo "4. ${BLUE}Using Security Tools${NC}"
  echo "   - Tools were pre-discovered during setup!"
  echo "   - Execute any tool: 'execute_nmap', 'execute_nikto', etc."
  echo "   - Example: Ask OpenCode to 'run nmap scan on example.com'"
  echo "   - Each execution runs in fresh isolated container"
  echo
  echo
  echo -e "${GREEN}=== TROUBLESHOOTING ===${NC}"
  echo "If tools don't appear in your AI assistant:"
  echo "1. Check Docker is running: docker ps"
  echo "2. Verify MCP Toolkit is enabled in Docker Desktop"
  echo "3. Restart your AI assistant completely"
  echo "4. Check container logs: docker logs \$(docker ps -q --filter name=kali-security)"
  echo "5. Verify server registration: docker mcp server list"
  echo "6. Check catalog file: cat $CUSTOM_CATALOG"
  echo "7. Check auto-start service status (see commands above)"
  echo
  echo "For issues, check the full README.md file in this directory."
}

# Main execution
main() {
  echo -e "${GREEN}=============================================================================${NC}"
  echo -e "${GREEN}   Kali Linux Security MCP Server - Automatic Setup Script${NC}"
  echo -e "${GREEN}=============================================================================${NC}"
  echo

  # Parse command-line arguments
  parse_arguments "$@"

  # Handle clean flag
  if [ "$CLEAN_SETUP" = "true" ]; then
    cleanup_all
  fi

  # Run setup steps
  check_prerequisites
  verify_mcp_prerequisites
  create_directories
  detect_client_config

  # Check what already exists
  check_existing_setup
  # Conditional builds based on checks
  build_docker_image
  set_docker_secrets
  configure_mcp_config
  create_custom_catalog
  enable_server
  warmup_tool_discovery
  update_client_config
  setup_docker_autostart
  create_systemd_service
  create_launchd_service

  if test_setup; then
    show_next_steps
  else
    print_error "Setup encountered errors. Please check the messages above."
    exit 1
  fi
}

# Function to verify MCP prerequisites
verify_mcp_prerequisites() {
  print_status "Verifying MCP prerequisites..."

  # Check if Docker MCP CLI is available
  if ! docker mcp --help &>/dev/null; then
    print_error "Docker MCP CLI plugin is not available"
    print_error "Please enable MCP Toolkit in Docker Desktop settings"
    print_error "Go to Docker Desktop → Settings → Beta Features → Enable 'Docker MCP Toolkit'"
    exit 1
  fi

  # Check if we can access MCP commands
  if ! docker mcp server list &>/dev/null; then
    print_warning "Docker MCP server list failed, but continuing..."
  fi

  print_success "MCP prerequisites verified"
}

# Check if running from correct directory
if [ ! -f "kali_server.py" ] || [ ! -f "Dockerfile" ]; then
  print_error "Please run this script from the kali-linux example directory"
  print_error "The script expects to find kali_server.py and Dockerfile in the current directory"
  exit 1
fi

# Run main function
main "$@"
