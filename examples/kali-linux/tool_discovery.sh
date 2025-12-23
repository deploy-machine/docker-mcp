#!/bin/bash
# Enhanced Tool Discovery Script for Kali Linux
# Uses multiple methods to find all available security tools

echo "=== KALI TOOL DISCOVERY ==="

# Method 1: Find all executable binaries
echo "[INFO] Discovering executable binaries..."
BINARIES=$(find /usr/bin /usr/sbin /usr/local/bin /opt -type f -executable 2>/dev/null | sort)
echo "[INFO] Found $(echo "$BINARIES" | wc -l) binaries"

# Method 2: Find desktop applications
echo "[INFO] Discovering desktop applications..."
DESKTOP_APPS=$(find /usr/share/applications -name '*.desktop' 2>/dev/null | xargs grep -l '^Exec=' 2>/dev/null | wc -l)
echo "[INFO] Found $DESKTOP_APPS desktop applications"

# Method 3: Get security-related packages
echo "[INFO] Discovering security packages..."
SECURITY_PACKAGES=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -E '(security|exploit|scan|crack|hack|pentest)' | wc -l)
echo "[INFO] Found $SECURITY_PACKAGES security packages"

# Method 4: Find Kali tool categories
echo "[INFO] Discovering Kali categories..."
KALI_CATEGORIES=$(find /usr/share/kali-menu -name '*.directory' 2>/dev/null | wc -l)
echo "[INFO] Found $KALI_CATEGORIES Kali categories"

# Method 5: Find Python security tools
echo "[INFO] Discovering Python tools..."
PYTHON_TOOLS=$(find /usr/share /opt -name '*.py' -executable 2>/dev/null | wc -l)
echo "[INFO] Found $PYTHON_TOOLS Python tools"

# Method 6: Find Perl security tools
echo "[INFO] Discovering Perl tools..."
PERL_TOOLS=$(find /usr/share /opt -name '*.pl' -executable 2>/dev/null | wc -l)
echo "[INFO] Found $PERL_TOOLS Perl tools"

# Output all binaries for Python processing
echo "$BINARIES"