# =============================================================================
# Kali Linux Dynamic MCP Server - Automatic Setup Script (Windows PowerShell)
# =============================================================================
# This script automates the entire setup process for the Kali Linux MCP server
# =============================================================================

param(
    [switch]$Clean,
    [switch]$Force,
    [switch]$Help
)

# Exit on error
$ErrorActionPreference = "Stop"

# Configuration variables
$KALI_BASE_IMAGE = "kalilinux/kali-rolling"
$KALI_READY_IMAGE = "kali-mcp-ready"
$SERVER_NAME = "kali-security"
$CONTAINER_PREFIX = "kali-security"
$TARGET_TIMEOUT = "120"
$HOME_DIR = $env:USERPROFILE
$MCP_DIR = Join-Path $HOME_DIR ".docker\mcp"
$CATALOGS_DIR = Join-Path $MCP_DIR "catalogs"
$REGISTRY_FILE = Join-Path $MCP_DIR "registry.yaml"
$KALI_CATALOG_NAME = "kali-security"
$KALI_CATALOG_FILE = Join-Path $CATALOGS_DIR "kali-security.yaml"
$SKIP_BUILD = $false
$SKIP_WARMUP = $false

# Color functions for output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Show-Usage {
    Write-Host "Usage: .\setup.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Clean         Delete all existing images, cache, and configs before setup"
    Write-Host "  -Force         Force rebuild even if images exist"
    Write-Host "  -Help          Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\setup.ps1                  # Normal run (prompts if images exist)"
    Write-Host "  .\setup.ps1 -Clean           # Complete clean install"
    Write-Host "  .\setup.ps1 -Force           # Force rebuild without prompts"
}

function Cleanup-All {
    Write-Status "Performing complete cleanup..."
    Write-Host ""
    Write-Warning "This will delete:"
    Write-Host "  - Docker images (kali-security-mcp-server, kali-mcp-ready)"
    Write-Host "  - Tool discovery cache"
    Write-Host "  - Catalog files"
    Write-Host "  - Server registrations"
    Write-Host ""
    $confirmation = Read-Host "Are you sure you want to continue? [y/N]"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        Write-Status "Cleanup cancelled"
        return
    }

    # Stop containers
    Write-Status "Stopping Kali containers..."
    docker ps -a | Select-String "kali-security" | ForEach-Object {
        $containerId = ($_ -split '\s+')[0]
        docker stop $containerId 2>$null
    }

    # Remove images
    Write-Status "Removing Docker images..."
    docker rmi kali-security-mcp-server:latest 2>$null
    docker rmi kali-mcp-ready:latest 2>$null

    # Remove cache
    Write-Status "Removing tool discovery cache..."
    $cachePath = Join-Path $MCP_DIR "kali-tools-cache.json"
    if (Test-Path $cachePath) {
        Remove-Item $cachePath -Force
    }

    # Remove catalog
    Write-Status "Removing catalog files..."
    if (Test-Path $KALI_CATALOG_FILE) {
        Remove-Item $KALI_CATALOG_FILE -Force
    }

    # Disable server
    Write-Status "Disabling MCP server..."
    docker mcp server disable kali-security 2>$null

    Write-Success "Cleanup complete!"
    Write-Host ""
}

function Check-ExistingSetup {
    Write-Status "Checking existing setup state..."
    
    $baseExists = $false
    $readyExists = $false
    $toolsDiscovered = $false

    # Check base MCP server image
    $images = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "kali-security-mcp-server:latest"
    if ($images) {
        Write-Success "Base image exists: kali-security-mcp-server:latest"
        $baseExists = $true
    } else {
        Write-Warning "Base image not found - will build"
    }

    # Check ready image
    $readyImages = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "$KALI_READY_IMAGE:latest"
    if ($readyImages) {
        Write-Success "Ready image exists: $KALI_READY_IMAGE:latest"
        $readyExists = $true
    } else {
        Write-Warning "Ready image not found - will build during warm-up"
    }

    # Check if tool discovery cache exists
    $cachePath = Join-Path $MCP_DIR "kali-tools-cache.json"
    if (Test-Path $cachePath) {
        Write-Success "Tool discovery cache found"
        $toolsDiscovered = $true
    } else {
        Write-Warning "Tool discovery cache not found - will discover"
    }

    # Decision matrix
    if ($baseExists -and $readyExists -and $toolsDiscovered) {
        Write-Success "Complete setup already exists!"
        Write-Host ""
        if (-not $Force) {
            $response = Read-Host "Skip rebuild and use existing setup? [Y/n]"
            if ([string]::IsNullOrEmpty($response) -or $response -eq 'Y' -or $response -eq 'y') {
                $script:SKIP_BUILD = $true
                $script:SKIP_WARMUP = $true
                return
            }
        }
    } elseif ($baseExists -and $readyExists) {
        Write-Success "Images exist, only tool discovery needed"
        $script:SKIP_BUILD = $true
        $script:SKIP_WARMUP = $false
    } elseif ($baseExists) {
        Write-Success "Base image exists, will build ready image"
        $script:SKIP_BUILD = $true
        $script:SKIP_WARMUP = $false
    }

    Write-Host ""
}

function Test-Prerequisites {
    Write-Status "Checking prerequisites..."

    # Check Docker
    try {
        $null = docker --version
    } catch {
        Write-Error "Docker is not installed or not in PATH"
        Write-Error "Please install Docker Desktop first: https://www.docker.com/products/docker-desktop/"
        exit 1
    }

    # Check if Docker daemon is running
    try {
        $null = docker info 2>&1
    } catch {
        Write-Error "Docker daemon is not running"
        Write-Error "Please start Docker Desktop"
        exit 1
    }

    Write-Success "Docker prerequisites satisfied"
}

function Test-MCPPrerequisites {
    Write-Status "Verifying MCP prerequisites..."

    # Check if Docker MCP CLI is available
    try {
        $null = docker mcp --help 2>&1
    } catch {
        Write-Error "Docker MCP CLI plugin is not available"
        Write-Error "Please enable MCP Toolkit in Docker Desktop settings"
        Write-Error "Go to Docker Desktop → Settings → Beta Features → Enable 'Docker MCP Toolkit'"
        exit 1
    }

    # Check if we can access MCP commands
    try {
        $null = docker mcp server list 2>&1
    } catch {
        Write-Warning "Docker MCP server list failed, but continuing..."
    }

    Write-Success "MCP prerequisites verified"
}

function New-Directories {
    Write-Status "Creating MCP directories..."

    if (-not (Test-Path $CATALOGS_DIR)) {
        New-Item -ItemType Directory -Path $CATALOGS_DIR -Force | Out-Null
    }
    
    $registryDir = Split-Path $REGISTRY_FILE -Parent
    if (-not (Test-Path $registryDir)) {
        New-Item -ItemType Directory -Path $registryDir -Force | Out-Null
    }

    Write-Success "Directories created"
}

function Build-DockerImage {
    # Check if base image already exists
    $images = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "kali-security-mcp-server:latest"
    if ($images) {
        Write-Status "Base image already exists - skipping build"
        return
    }

    Write-Status "Building Kali Linux Security MCP Server image..."
    Write-Warning "This may take 15-30 minutes on first build"
    
    $scriptPath = Split-Path -Parent $MyInvocation.ScriptName
    Push-Location $scriptPath
    
    try {
        docker build -t "kali-security-mcp-server" .
        if ($LASTEXITCODE -ne 0) {
            throw "Docker build failed"
        }
        Write-Success "Docker image built successfully"
    } catch {
        Write-Error "Failed to build Docker image"
        exit 1
    } finally {
        Pop-Location
    }
}

function Set-DockerSecrets {
    Write-Status "Setting Docker MCP secrets..."

    docker mcp secret set KALI_TARGET_TIMEOUT="$TARGET_TIMEOUT" 2>$null
    docker mcp secret set KALI_CONTAINER_PREFIX="$CONTAINER_PREFIX" 2>$null
    docker mcp secret set KALI_BASE_IMAGE="kali-security-mcp-server:latest" 2>$null
    docker mcp secret set KALI_READY_IMAGE="$KALI_READY_IMAGE" 2>$null

    Write-Success "Docker secrets configured"
}

function Set-MCPConfig {
    Write-Status "Configuring MCP config.yaml for kali-security..."
    
    $configFile = Join-Path $MCP_DIR "config.yaml"
    
    # Create config.yaml if it doesn't exist
    if (-not (Test-Path $configFile)) {
        New-Item -ItemType File -Path $configFile -Force | Out-Null
    }
    
    # Check if kali-security config already exists
    $configContent = Get-Content $configFile -Raw -ErrorAction SilentlyContinue
    if ($configContent -match "^kali-security:") {
        Write-Status "kali-security config already exists, updating..."
        # Remove old config section - simple approach: rewrite file
        $lines = Get-Content $configFile
        $newLines = @()
        $skip = $false
        foreach ($line in $lines) {
            if ($line -match "^kali-security:") {
                $skip = $true
            } elseif ($skip -and $line -match "^[^ ]") {
                $skip = $false
            }
            if (-not $skip) {
                $newLines += $line
            }
        }
        $newLines | Set-Content $configFile
    }
    
    # Append kali-security configuration
    $config = @"
kali-security:
  KALI_BASE_IMAGE: "kali-security-mcp-server:latest"
  KALI_CONTAINER_PREFIX: "$CONTAINER_PREFIX"
  KALI_TARGET_TIMEOUT: "$TARGET_TIMEOUT"
  KALI_READY_IMAGE: "$KALI_READY_IMAGE"
"@
    Add-Content -Path $configFile -Value $config
    
    Write-Success "MCP config.yaml updated with kali-security settings"
}

function Start-ToolDiscoveryWarmup {
    # Check if ready image and cache already exist
    $readyExists = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "kali-mcp-ready:latest"
    $cachePath = Join-Path $MCP_DIR "kali-tools-cache.json"
    $cacheExists = Test-Path $cachePath

    if ($readyExists -and $cacheExists) {
        Write-Success "Ready image and tool cache already exist - skipping warm-up"
        return
    }

    Write-Status "Running tool discovery warm-up..."

    if ($readyExists) {
        Write-Success "Ready image already exists, only running tool discovery"
        Write-Status "This should be fast (~2-3 minutes)"
    } else {
        Write-Warning "Ready image not found - will install kali-linux-everything"
        Write-Warning "This process can take 10-30 minutes depending on your system"
    }

    Write-Warning "Please be patient - this makes first-time usage instant!"

    # Start temporary container
    $warmupContainer = "$CONTAINER_PREFIX-warmup-$PID"

    Write-Status "Starting warm-up container..."
    
    # Convert Windows path to format Docker understands
    $mcpDirDocker = $MCP_DIR -replace '\\', '/'
    if ($mcpDirDocker -match '^[A-Z]:') {
        $mcpDirDocker = $mcpDirDocker -replace '^([A-Z]):', { '/mnt/' + $_.Groups[1].Value.ToLower() }
    }

    docker run -d `
        --name $warmupContainer `
        --rm `
        -e KALI_TARGET_TIMEOUT="$TARGET_TIMEOUT" `
        -e KALI_CONTAINER_PREFIX="$CONTAINER_PREFIX" `
        -e KALI_BASE_IMAGE="kali-security-mcp-server:latest" `
        -e KALI_READY_IMAGE="$KALI_READY_IMAGE" `
        -e KALI_SKIP_BUILD="$readyExists" `
        -e KALI_CACHE_FILE="/mcp/kali-tools-cache.json" `
        -v "$($MCP_DIR):/mcp" `
        -v /var/run/docker.sock:/var/run/docker.sock `
        "kali-security-mcp-server:latest" `
        tail -f /dev/null

    # Wait for container to be ready
    Start-Sleep -Seconds 3

    # Execute warm-up script
    Write-Status "Executing tool discovery..."
    
    $pythonScript = @"
import sys
sys.path.insert(0, '/app')
from kali_server import discover_kali_tools_optimized, logger
logger.info('Starting OPTIMIZED tool discovery warm-up...')
result = discover_kali_tools_optimized(force_refresh=True)
logger.info(f'Discovered {len(result[\"tools\"])} tools in {len(result[\"categories\"])} categories')
logger.info('Warm-up complete!')
print(f'WARMUP_COMPLETE:{len(result[\"tools\"])}')
"@

    $logFile = Join-Path $env:TEMP "kali-warmup.log"
    
    # Run discovery in background
    $job = Start-Job -ScriptBlock {
        param($container, $script, $log)
        docker exec $container python -c $script 2>&1 | Tee-Object -FilePath $log
    } -ArgumentList $warmupContainer, $pythonScript, $logFile

    Write-Host ""
    Write-Status "Discovery in progress (Job ID: $($job.Id))..."
    if ($readyExists) {
        Write-Status "Using existing ready image (fast path)"
    } else {
        Write-Status "Installing packages and discovering tools (slow path)"
    }
    Write-Host ""

    # Wait for completion with timeout
    $timeout = 1800 # 30 minutes
    $elapsed = 0
    
    while ($job.State -eq 'Running') {
        if ($elapsed -ge $timeout) {
            Write-Error "Warm-up timed out after $timeout seconds (30 minutes)"
            Stop-Job $job
            docker stop $warmupContainer 2>$null
            Remove-Item $logFile -ErrorAction SilentlyContinue
            return
        }

        if ($elapsed % 30 -eq 0) {
            Write-Host "`n[$elapsed s elapsed]" -NoNewline
        }
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 5
        $elapsed += 5
    }
    Write-Host ""

    # Check results
    if (Test-Path $logFile) {
        $logContent = Get-Content $logFile -Raw
        if ($logContent -match "WARMUP_COMPLETE:(\d+)") {
            $toolCount = $matches[1]
            Write-Success "Tool discovery complete! Found $toolCount tools"
            Write-Success "Cache saved to $cachePath"
            Write-Success "These will be available immediately when you start your AI client"
        } else {
            Write-Warning "Warm-up completed but results unclear"
            Write-Warning "Tools will still be discovered on first use"
        }
        Remove-Item $logFile -ErrorAction SilentlyContinue
    }

    # Cleanup
    Write-Status "Cleaning up warm-up container..."
    docker stop $warmupContainer 2>$null
    Remove-Job $job -Force
}

function New-CustomCatalog {
    # Check if catalog already imported
    try {
        docker mcp catalog show $KALI_CATALOG_NAME 2>&1 | Out-Null
        Write-Success "Catalog already imported - skipping"
        return
    } catch {
        # Catalog doesn't exist, continue
    }

    Write-Status "Creating Kali Security MCP catalog..."

    $catalogContent = @'
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
'@

    Set-Content -Path $KALI_CATALOG_FILE -Value $catalogContent
    Write-Success "Catalog file created at $KALI_CATALOG_FILE"

    # Import catalog
    Write-Status "Importing catalog into Docker MCP..."
    try {
        docker mcp catalog import $KALI_CATALOG_FILE
        Write-Success "Catalog imported successfully"
    } catch {
        Write-Error "Failed to import catalog"
        Write-Error "Manual import: docker mcp catalog import $KALI_CATALOG_FILE"
        exit 1
    }
}

function Enable-Server {
    # Check if server already enabled
    $servers = docker mcp server ls 2>&1 | Select-String $SERVER_NAME
    if ($servers) {
        Write-Success "Server already enabled - skipping"
        return
    }

    Write-Status "Enabling Kali Security MCP server..."

    try {
        docker mcp server enable $SERVER_NAME
        Write-Success "Server enabled successfully"
    } catch {
        Write-Error "Failed to enable server"
        Write-Error "Manual enable: docker mcp server enable $SERVER_NAME"
        exit 1
    }

    # Verify registry
    if (Test-Path $REGISTRY_FILE) {
        $registryContent = Get-Content $REGISTRY_FILE -Raw
        if ($registryContent -match $SERVER_NAME) {
            Write-Success "Server registered in registry.yaml"
        } else {
            Write-Warning "Server may not be in registry.yaml, but Docker MCP tracks it internally"
        }
    }
}

function Update-ClientConfig {
    Write-Status "Detecting AI client configuration..."

    # Check for Claude Desktop
    $claudeConfigPath = Join-Path $env:APPDATA "Claude\claude_desktop_config.json"
    
    if (Test-Path $claudeConfigPath) {
        Update-ClaudeConfig $claudeConfigPath
    } else {
        Write-Warning "Claude Desktop config not found at $claudeConfigPath"
        Write-Warning "You may need to manually configure your AI client"
    }
}

function Update-ClaudeConfig {
    param([string]$ConfigPath)
    
    Write-Status "Updating Claude Desktop configuration..."

    # Create backup
    if (Test-Path $ConfigPath) {
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        Copy-Item $ConfigPath "$ConfigPath.backup.$timestamp"
        Write-Warning "Backup of existing config created"
    }

    # Convert Windows path for Docker
    $homeDirDocker = $HOME_DIR -replace '\\', '/'
    if ($homeDirDocker -match '^[A-Z]:') {
        $homeDirDocker = $homeDirDocker -replace '^([A-Z]):', { '/mnt/' + $_.Groups[1].Value.ToLower() }
    }

    $config = @{
        mcpServers = @{
            "mcp-toolkit-gateway" = @{
                command = "docker"
                args = @(
                    "run",
                    "-i",
                    "--rm",
                    "-v", "/var/run/docker.sock:/var/run/docker.sock",
                    "-v", "$homeDirDocker/.docker/mcp:/mcp",
                    "docker/mcp-gateway",
                    "--catalog=/mcp/catalogs/docker-mcp.yaml",
                    "--catalog=/mcp/catalogs/kali-security.yaml",
                    "--config=/mcp/config.yaml",
                    "--registry=/mcp/registry.yaml",
                    "--tools-config=/mcp/tools.yaml",
                    "--transport=stdio"
                )
            }
        }
    }

    $config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath
    Write-Success "Claude Desktop configuration updated"
}

function Test-Setup {
    Write-Status "Testing the setup..."

    # Test 1: Docker image
    $images = docker images | Select-String "kali-security-mcp-server"
    if ($images) {
        Write-Success "Docker image is available"
    } else {
        Write-Error "Docker image not found"
        return $false
    }

    # Test 2: Catalog file
    if (Test-Path $KALI_CATALOG_FILE) {
        Write-Success "Catalog file exists"
    } else {
        Write-Error "Catalog file missing"
        return $false
    }

    # Test 3: Catalog imported
    try {
        docker mcp catalog show $KALI_CATALOG_NAME 2>&1 | Out-Null
        Write-Success "Catalog is imported in Docker MCP"
    } catch {
        Write-Error "Catalog not imported in Docker MCP"
        return $false
    }

    # Test 4: Server enabled
    $servers = docker mcp server ls 2>&1 | Select-String $SERVER_NAME
    if ($servers) {
        Write-Success "Server is enabled"
    } else {
        Write-Error "Server not enabled"
        return $false
    }

    return $true
}

function Show-NextSteps {
    Write-Success "Setup completed successfully!"
    Write-Host ""
    Write-Host "=== NEXT STEPS ===" -ForegroundColor Green
    Write-Host ""
    Write-Host "1. " -NoNewline
    Write-Host "Restart Claude Desktop" -ForegroundColor Blue
    Write-Host "   - Completely quit Claude Desktop"
    Write-Host "   - Start Claude Desktop again"
    Write-Host ""
    Write-Host "2. " -NoNewline
    Write-Host "Wait for Tool Discovery" -ForegroundColor Blue
    Write-Host "   - First run may take 1-2 minutes"
    Write-Host "   - Tools were pre-discovered during setup!"
    Write-Host ""
    Write-Host "3. " -NoNewline
    Write-Host "Start Using" -ForegroundColor Blue
    Write-Host "   - Ask Claude: 'List all security tools'"
    Write-Host "   - Try: 'Get help for nmap'"
    Write-Host "   - Try: 'Search for web testing tools'"
    Write-Host ""
    Write-Host "=== IMPORTANT LEGAL NOTICE ===" -ForegroundColor Yellow
    Write-Host "This server provides access to professional security testing tools."
    Write-Host "ONLY use on systems you own or have explicit permission to test."
    Write-Host "Unauthorized use may be illegal and result in prosecution."
    Write-Host ""
    Write-Host "=== VERIFICATION COMMANDS ===" -ForegroundColor Green
    Write-Host "Check if everything is working:"
    Write-Host "  docker images | Select-String kali-security-mcp-server"
    Write-Host "  docker mcp catalog show kali-security"
    Write-Host "  docker mcp server ls | Select-String kali-security"
    Write-Host ""
    Write-Host "=== TROUBLESHOOTING ===" -ForegroundColor Green
    Write-Host "If tools don't appear:"
    Write-Host "1. Check Docker is running: docker ps"
    Write-Host "2. Verify MCP Toolkit is enabled in Docker Desktop"
    Write-Host "3. Restart Claude completely"
    Write-Host "4. Check logs: docker logs `$(docker ps -q --filter name=kali-security)"
    Write-Host ""
}

# Main execution
function Main {
    Write-Host "=============================================================================" -ForegroundColor Green
    Write-Host "   Kali Linux Security MCP Server - Automatic Setup Script (Windows)" -ForegroundColor Green
    Write-Host "=============================================================================" -ForegroundColor Green
    Write-Host ""

    if ($Help) {
        Show-Usage
        exit 0
    }

    # Handle clean flag
    if ($Clean) {
        Cleanup-All
    }

    # Run setup steps
    Test-Prerequisites
    Test-MCPPrerequisites
    New-Directories
    
    # Check what already exists
    Check-ExistingSetup
    
    # Conditional builds
    if (-not $SKIP_BUILD) {
        Build-DockerImage
    }
    
    Set-DockerSecrets
    Set-MCPConfig
    New-CustomCatalog
    Enable-Server
    
    if (-not $SKIP_WARMUP) {
        Start-ToolDiscoveryWarmup
    }
    
    Update-ClientConfig

    if (Test-Setup) {
        Show-NextSteps
    } else {
        Write-Error "Setup encountered errors. Please check the messages above."
        exit 1
    }
}

# Check if running from correct directory
if (-not (Test-Path "kali_server.py") -or -not (Test-Path "Dockerfile")) {
    Write-Error "Please run this script from the kali-linux example directory"
    Write-Error "The script expects to find kali_server.py and Dockerfile in the current directory"
    exit 1
}

# Run main function
Main
