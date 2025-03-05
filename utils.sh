#!/bin/bash

# Utility functions for CrowdSec Manager

# Terminal colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}   $1${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
}

# Function to print success message
print_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

# Function to print warning message
print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# Function to print error message
print_error() {
    echo -e "${RED}[-] $1${NC}"
}

# Function to print info message
print_info() {
    echo -e "${CYAN}[*] $1${NC}"
}

# Function to check if a container is running
check_container() {
    local container=$1
    if docker ps | grep "$container"; then
        print_success "$container container is running"
        return 0
    else
        print_error "$container container is NOT running"
        return 1
    fi
}

# Function to run a command and display its output
run_command() {
    local cmd=$1
    local header=$2
    
    echo -e "${YELLOW}$header${NC}"
    echo -e "${CYAN}Command: $cmd${NC}"
    echo -e "${CYAN}Output:${NC}"
    
    eval "$cmd" || {
        local exit_code=$?
        print_error "Command failed with exit code $exit_code"
        return $exit_code
    }
    
    echo ""
    return 0
}

# Function to ask for confirmation
confirm_action() {
    local message=$1
    echo -ne "${YELLOW}$message [y/N]:${NC} "
    read -r answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to press enter to continue
press_enter_to_continue() {
    echo ""
    echo -ne "${YELLOW}Press Enter to continue...${NC}"
    read -r
}

# Cleanup function for temporary files
cleanup() {
    rm -rf "${TEMP_DIR}"
    print_info "Temporary files cleaned up."
}

# IP validation and handling functions
validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -r a b c d <<< "$ip"
        [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]] && return 0
    fi
    return 1
}

# Convert IP address to integer for comparison
ip_to_int() {
    local ip="$1"
    local IFS='.'
    read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# Check if an IP is within a subnet (supports CIDR notation)
is_ip_in_subnet() {
    local ip="$1"
    local subnet="$2"
    if [[ "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        [[ "$ip" == "$subnet" ]] && return 0 || return 1
    fi
    if [[ "$subnet" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$ ]]; then
        local subnet_ip="${BASH_REMATCH[1]}"
        local prefix_size="${BASH_REMATCH[2]}"
        [[ "$prefix_size" -lt 0 || "$prefix_size" -gt 32 ]] && return 1
        local ip_int=$(ip_to_int "$ip")
        local subnet_int=$(ip_to_int "$subnet_ip")
        local mask=$((0xffffffff << (32 - prefix_size)))
        [[ $((ip_int & mask)) -eq $((subnet_int & mask)) ]] && return 0 || return 1
    fi
    return 1
}

# Check if an IP is whitelisted in a file
is_ip_whitelisted_in_file() {
    local ip="$1"
    local file="$2"
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    local ip_patterns
    ip_patterns=$(grep -oE '"([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?"|([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$file" | tr -d '"' | sort -u)
    while read -r subnet; do
        if [[ -n "$subnet" ]] && is_ip_in_subnet "$ip" "$subnet"; then
            return 0
        fi
    done <<< "$ip_patterns"
    return 1
}

# Get current public IP
get_public_ip() {
    local ip
    ip=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null)
    if validate_ip "$ip"; then
        echo "$ip"
    else
        print_error "Failed to retrieve a valid public IP."
        return 1
    fi
}
