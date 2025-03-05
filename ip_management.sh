#!/bin/bash

# Function for unban manual IP submenu
unban_manual_ip() {
    print_header "UNBAN AN IP"
    echo -ne "${YELLOW}Enter the IP address to unban: ${NC}"
    local ip
    read -r ip
    if ! validate_ip "$ip"; then
        print_error "Invalid IP address format."
        return 1
    fi
    unban_ip "$ip"
    return $?
}

# Function to check IP security status
check_ip_security() {
    print_header "SECURITY CHECK FOR IP"
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot check IP security status."
        return 1
    fi

    echo -ne "${YELLOW}Enter the IP address to check: ${NC}"
    local ip
    read -r ip
    if ! validate_ip "$ip"; then
        print_error "Invalid IP address format. Please enter a valid IPv4 address."
        return 1
    fi

    if is_ip_blocked "$ip"; then
        print_warning "IP $ip is currently BLOCKED by CrowdSec."
        print_info "Decision details:"
        ( docker exec crowdsec cscli decisions list -o human | grep "$ip" ) || true
    else
        print_success "IP $ip is NOT currently blocked by CrowdSec."
    fi

    local crowdsec_whitelist="/etc/crowdsec/parsers/s02-enrich/whitelists.yaml"
    local ip_whitelisted_in_crowdsec=1
    if docker exec crowdsec test -f "$crowdsec_whitelist" 2>/dev/null; then
        docker cp "crowdsec:$crowdsec_whitelist" "${TEMP_DIR}/check_whitelist.yaml" 2>/dev/null
        if [[ -f "${TEMP_DIR}/check_whitelist.yaml" ]]; then
            if is_ip_whitelisted_in_file "$ip" "${TEMP_DIR}/check_whitelist.yaml"; then
                print_success "IP $ip is whitelisted in CrowdSec (likely part of a subnet)."
                ip_whitelisted_in_crowdsec=0
            else
                print_warning "IP $ip is NOT whitelisted in CrowdSec."
            fi
        fi
    else
        print_warning "No CrowdSec whitelist file found."
    fi

    if [[ -f "$TRAEFIK_CONFIG_PATH" ]]; then
        if is_ip_whitelisted_in_file "$ip" "$TRAEFIK_CONFIG_PATH"; then
            print_success "IP $ip is whitelisted in Traefik configuration (likely part of a subnet)."
        else
            print_warning "IP $ip is NOT whitelisted in Traefik configuration."
        fi
    else
        print_warning "Traefik configuration file not found."
    fi

    return 0
}
