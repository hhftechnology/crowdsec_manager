#!/bin/bash

# Functions related to CrowdSec decisions

# Function to check if an IP is blocked
is_ip_blocked() {
    local ip="$1"
    if ! check_container "crowdsec"; then
        return 1
    fi
    docker exec crowdsec cscli decisions list -o human | grep -q "$ip"
    return $?
}

# Function to check and list CrowdSec decisions
check_crowdsec_decisions() {
    print_header "CHECKING CROWDSEC DECISIONS"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot check decisions."
        return 1
    fi
    
    run_command "docker exec crowdsec cscli decisions list -o human" "Listing active CrowdSec decisions (blocks/captchas)"
    
    echo -e "${YELLOW}Note: If there are no decisions, it means no malicious activity has been detected yet.${NC}"
    echo -e "${YELLOW}This does not necessarily indicate a problem with CrowdSec.${NC}"
    
    echo ""
    return 0
}

# Function to unban an IP
unban_ip() {
    print_header "UNBAN IP ADDRESS"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot unban IP."
        return 1
    fi

    local ip="$1"
    if [ -z "$ip" ]; then
        echo -ne "${YELLOW}Enter the IP address to unban: ${NC}"
        read -r ip
    fi
    
    if ! validate_ip "$ip"; then
        print_error "Invalid IP address format: $ip"
        return 1
    fi
    
    print_info "Checking if IP $ip is currently banned..."
    if is_ip_blocked "$ip"; then
        echo -e "${YELLOW}Removing ban for IP $ip...${NC}"
        docker exec crowdsec cscli decisions delete --ip "$ip" || {
            print_error "Failed to unban IP $ip."
            return 1
        }
        print_success "IP $ip has been unbanned from CrowdSec."
    else
        print_info "IP $ip is not currently banned."
    fi
    
    return 0
}
