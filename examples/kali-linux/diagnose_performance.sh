#!/bin/bash
# Performance Diagnostic Script for Kali MCP Server
# This script helps diagnose why tool discovery is slow

echo "================================"
echo "Kali MCP Performance Diagnostics"
echo "================================"
echo ""

# Check if we're inside the container or on the host
if [ -f "/etc/kali_version" ] || [ -f "/.dockerenv" ]; then
    echo "✅ Running inside Kali container"
    CONTEXT="container"
else
    echo "⚠️  Running on host system (not in container)"
    CONTEXT="host"
fi
echo ""

# 1. Count total executables
echo "1️⃣  Counting executable binaries..."
START=$(date +%s)
BINARY_COUNT=$(find /usr/bin /usr/sbin /usr/local/bin -type f -executable 2>/dev/null | wc -l)
END=$(date +%s)
BINARY_TIME=$((END - START))
echo "   Found: ${BINARY_COUNT} executables"
echo "   Time: ${BINARY_TIME}s"
echo ""

# 2. Test find performance in /opt (can be slow)
echo "2️⃣  Testing /opt scan (potential bottleneck)..."
START=$(date +%s)
OPT_COUNT=$(find /opt -type f -executable 2>/dev/null | wc -l)
END=$(date +%s)
OPT_TIME=$((END - START))
echo "   Found: ${OPT_COUNT} executables in /opt"
echo "   Time: ${OPT_TIME}s"
if [ $OPT_TIME -gt 10 ]; then
    echo "   ⚠️  WARNING: /opt scan is SLOW (${OPT_TIME}s) - consider excluding"
fi
echo ""

# 3. Count Python tools
echo "3️⃣  Counting Python security tools..."
START=$(date +%s)
PYTHON_COUNT=$(find /usr/share -maxdepth 3 -name '*.py' -executable 2>/dev/null | wc -l)
END=$(date +%s)
PYTHON_TIME=$((END - START))
echo "   Found: ${PYTHON_COUNT} Python scripts"
echo "   Time: ${PYTHON_TIME}s"
echo ""

# 4. Check if cache exists
echo "4️⃣  Checking for tool cache..."
CACHE_FILE="${KALI_CACHE_FILE:-/mcp/kali-tools-cache.json}"
if [ -f "$CACHE_FILE" ]; then
    echo "   ✅ Cache file exists: $CACHE_FILE"
    echo "   Size: $(du -h "$CACHE_FILE" | cut -f1)"
    echo "   Modified: $(stat -c %y "$CACHE_FILE" 2>/dev/null || stat -f %Sm "$CACHE_FILE" 2>/dev/null)"
    
    # Count tools in cache
    if command -v jq &> /dev/null; then
        CACHED_TOOLS=$(jq '.tools | length' "$CACHE_FILE" 2>/dev/null)
        echo "   Tools in cache: ${CACHED_TOOLS}"
    fi
else
    echo "   ⚠️  No cache file found at $CACHE_FILE"
    echo "   First run will be slow - cache will be created"
fi
echo ""

# 5. Docker performance check
echo "5️⃣  Docker performance check..."
if command -v docker &> /dev/null; then
    echo "   Docker version: $(docker --version)"
    
    # Check if we're scanning from inside a container
    if [ "$CONTEXT" = "container" ]; then
        echo "   ✅ Already in container - filesystem scan is direct"
    else
        echo "   ⚠️  Running on host - tool discovery may spawn containers"
    fi
else
    echo "   ⚠️  Docker not found in PATH"
fi
echo ""

# 6. Estimate total discovery time
echo "6️⃣  Estimated discovery time:"
TOTAL_ESTIMATE=$((BINARY_TIME + OPT_TIME + PYTHON_TIME))
echo "   Filesystem scan: ~${TOTAL_ESTIMATE}s"
echo "   Tool categorization: ~10-30s (depends on CPU cores)"
echo "   First-run total (no cache): ~$((TOTAL_ESTIMATE + 20))s"
echo "   With cache: <2s"
echo ""

# 7. System resources
echo "7️⃣  System resources:"
echo "   CPU cores: $(nproc)"
echo "   Memory: $(free -h | grep Mem | awk '{print $2}' 2>/dev/null || echo 'N/A')"
echo ""

# 8. Recommendations
echo "8️⃣  Recommendations:"
echo ""
if [ $BINARY_COUNT -gt 5000 ]; then
    echo "   ⚠️  HIGH: Very large number of binaries (${BINARY_COUNT})"
    echo "   → Consider excluding /opt from initial scan"
    echo "   → Use category-based filtering"
fi

if [ ! -f "$CACHE_FILE" ]; then
    echo "   💡 No cache found - first run will be slow"
    echo "   → Run tool discovery once to build cache"
    echo "   → Subsequent runs will be <2s"
fi

if [ $OPT_TIME -gt 10 ]; then
    echo "   ⚠️  /opt directory scan is slow (${OPT_TIME}s)"
    echo "   → Modify discover_kali_tools() to exclude /opt"
fi

echo ""
echo "   ✅ Use the optimized version (kali_server_optimized.py) for:"
echo "   → Parallel tool categorization"
echo "   → Progress indicators"
echo "   → Faster startup time"
echo ""

# 9. Quick performance comparison
echo "9️⃣  Performance comparison test:"
echo ""
echo "   Testing sequential vs parallel categorization..."

# Create test data
TEST_TOOLS=$(find /usr/bin -type f -executable 2>/dev/null | head -100 | xargs -n1 basename)
TOOL_COUNT=$(echo "$TEST_TOOLS" | wc -l)

# Sequential
START=$(date +%s%N)
for tool in $TEST_TOOLS; do
    echo "$tool" | grep -qE "(nmap|scan|sql|hack)" && continue
done
END=$(date +%s%N)
SEQ_TIME=$(( (END - START) / 1000000 ))

echo "   Sequential processing (${TOOL_COUNT} tools): ${SEQ_TIME}ms"
echo "   Estimated for ${BINARY_COUNT} tools: ~$((SEQ_TIME * BINARY_COUNT / TOOL_COUNT))ms"
echo "   With 10 parallel workers: ~$((SEQ_TIME * BINARY_COUNT / TOOL_COUNT / 10))ms"
echo ""

echo "================================"
echo "Diagnostic complete!"
echo "================================"
