#!/bin/bash

# Function to add IP to CrowdSec whitelist
add_to_crowdsec_whitelist() {
    local ip="$1"
    local whitelist_path="/etc/crowdsec/parsers/s02-enrich/whitelists.yaml"
    print_info "Adding IP $ip to CrowdSec whitelist..."

    if docker exec crowdsec test -f "$whitelist_path" 2>/dev/null; then
        print_info "Existing whitelist found, checking if IP is already whitelisted..."
        docker cp "crowdsec:$whitelist_path" "${TEMP_WHITELIST}.orig" 2>/dev/null
        if [[ -f "${TEMP_WHITELIST}.orig" ]]; then
            if is_ip_whitelisted_in_file "$ip" "${TEMP_WHITELIST}.orig"; then
                print_info "IP $ip is already whitelisted in CrowdSec through an existing entry."
                rm -f "${TEMP_WHITELIST}.orig"
                return 0
            fi
        fi
    fi

    cat > "${TEMP_WHITELIST}" << EOF
---
name: crowdsecurity/whitelists
description: "Whitelist configuration for trusted IPs and users"
whitelist:
  reason: "trusted sources"
  ip:
    - "$ip"  # Added by IP Management script
EOF

    if [[ -f "${TEMP_WHITELIST}.orig" ]]; then
        awk -v ip="$ip" 'BEGIN{found=0} /ip:/{p=1} p==1 && /^ *- /{if (!found) {print "    - \"" ip "\"  # Added by IP Management script"; found=1}} {print}' "${TEMP_WHITELIST}.orig" > "${TEMP_WHITELIST}"
        rm -f "${TEMP_WHITELIST}.orig"
    else
        print_info "No existing whitelist found, creating new one..."
    fi

    if ! docker cp "${TEMP_WHITELIST}" "crowdsec:$whitelist_path"; then
        print_error "Failed to copy whitelist to container."
        return 1
    fi
    print_info "Restarting CrowdSec to apply changes..."
    if ! docker restart crowdsec; then
        print_error "Failed to restart CrowdSec. Please check the container logs."
        return 1
    fi
    sleep 2
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container failed to restart."
        return 1
    fi
    print_success "IP $ip has been added to the CrowdSec whitelist."
    return 0
}

# Function to add IP to Traefik whitelist
add_to_traefik_whitelist() {
    local ip="$1"
    print_info "Adding IP $ip to Traefik whitelist..."
    if [[ ! -f "$TRAEFIK_CONFIG_PATH" ]]; then
        print_error "Traefik configuration file not found at $TRAEFIK_CONFIG_PATH"
        return 1
    fi

    if is_ip_whitelisted_in_file "$ip" "$TRAEFIK_CONFIG_PATH"; then
        print_info "IP $ip is already whitelisted in Traefik configuration through an existing entry."
        return 0
    fi

    cp "$TRAEFIK_CONFIG_PATH" "${TRAEFIK_CONFIG_PATH}.bak"
    cp "$TRAEFIK_CONFIG_PATH" "$TEMP_CONFIG"
    local updated=0

    if grep -q "clientTrustedIPs:" "$TEMP_CONFIG"; then
        print_info "Updating clientTrustedIPs section..."
        awk '/clientTrustedIPs:/,/[^-]/{if (/^ +- /) last=$0} {print} END{if (last) print "            - '"$ip"'  # Added by IP Management script"}' "$TEMP_CONFIG" > "${TEMP_CONFIG}.new"
        mv "${TEMP_CONFIG}.new" "$TEMP_CONFIG"
        updated=1
    fi
    if grep -q "sourceRange:" "$TEMP_CONFIG"; then
        print_info "Updating sourceRange section..."
        awk '/sourceRange:/,/[^-]/{if (/^ +- /) last=$0} {print} END{if (last) print "          - '"$ip"'  # Added by IP Management script"}' "$TEMP_CONFIG" > "${TEMP_CONFIG}.new"
        mv "${TEMP_CONFIG}.new" "$TEMP_CONFIG"
        updated=1
    fi
    if grep -q "forwardedHeadersTrustedIPs:" "$TEMP_CONFIG"; then
        print_info "Updating forwardedHeadersTrustedIPs section..."
        awk '/forwardedHeadersTrustedIPs:/,/[^-]/{if (/^ +- /) last=$0} {print} END{if (last) print "            - '"$ip"'  # Added by IP Management script"}' "$TEMP_CONFIG" > "${TEMP_CONFIG}.new"
        mv "${TEMP_CONFIG}.new" "$TEMP_CONFIG"
        updated=1
    fi

    if [[ $updated -eq 0 ]]; then
        print_error "Could not find appropriate sections to update in Traefik config."
        return 1
    fi

    cp "$TEMP_CONFIG" "$TRAEFIK_CONFIG_PATH"
    print_info "Restarting Traefik to apply changes..."
    if ! docker restart traefik; then
        print_error "Failed to restart Traefik. Restoring backup..."
        cp "${TRAEFIK_CONFIG_PATH}.bak" "$TRAEFIK_CONFIG_PATH"
        return 1
    fi
    sleep 2
    if ! check_container "traefik"; then
        print_error "Traefik container failed to restart. Restoring backup..."
        cp "${TRAEFIK_CONFIG_PATH}.bak" "$TRAEFIK_CONFIG_PATH"
        docker restart traefik
        return 1
    fi
    print_success "IP $ip has been added to the Traefik whitelist."
    return 0
}

# Function to set up IP whitelisting
setup_whitelist() {
    print_header "SETTING UP IP WHITELISTING"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot set up whitelist."
        return 1
    fi

    echo -e "${CYAN}Select a whitelisting option:${NC}"
    echo -e "${CYAN}1.${NC} Whitelist current public IP"
    echo -e "${CYAN}2.${NC} Whitelist a specific IP"
    echo -e "${CYAN}3.${NC} Set up comprehensive whitelist with standard private networks"
    echo -e "${CYAN}4.${NC} View currently whitelisted IPs"
    echo -e "${CYAN}0.${NC} Return to main menu"
    echo -ne "${YELLOW}Enter your choice [0-4]:${NC} "
    read -r whitelist_choice
    
    case $whitelist_choice in
        1) 
            whitelist_current_ip
            return $?
            ;;
        2) 
            whitelist_manual_ip
            return $?
            ;;
        3)
            ;;
        4)
            view_whitelisted
            return $?
            ;;
        0)
            return 0
            ;;
        *)
            print_error "Invalid option. Please try again."
            return 1
            ;;
    esac
    
    echo -ne "${YELLOW}Do you want to add additional IP addresses to the whitelist? [y/N]:${NC} "
    read -r answer
    
    ADDITIONAL_IPS=""
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Enter IP addresses/ranges (one per line, press Ctrl+D when done):${NC}"
        ADDITIONAL_IPS=$(cat)
    fi
    
    WHITELIST_FILE="${TEMP_DIR}/whitelists.yaml"
    echo -e "${YELLOW}Creating whitelist configuration...${NC}"
    cat > "$WHITELIST_FILE" << EOF
---
name: crowdsecurity/whitelists
description: "Whitelist configuration for trusted IPs and users"
whitelist:
  reason: "trusted sources"
  ip:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "100.89.137.0/20"   
EOF

    if [[ -n "$ADDITIONAL_IPS" ]]; then
        echo "$ADDITIONAL_IPS" | while read -r ip; do
            if [[ -n "$ip" ]]; then
                echo "    - \"$ip\"" >> "$WHITELIST_FILE"
            fi
        done
    fi
    
    cat >> "$WHITELIST_FILE" << 'EOF'
  expression:
    - evt.Parsed.source_ip == '127.0.0.1'
    - evt.Parsed.source_ip contains '172.17.'
EOF

    echo -e "${YELLOW}Copying whitelist to CrowdSec container...${NC}"
    docker cp "$WHITELIST_FILE" crowdsec:/etc/crowdsec/parsers/s02-enrich/ || {
        print_error "Failed to copy whitelist file to CrowdSec container."
        return 1
    }

    echo -e "${YELLOW}Restarting CrowdSec to apply whitelist...${NC}"
    docker restart crowdsec || {
        print_error "Failed to restart CrowdSec container."
        return 1
    }
    
    sleep 5
    
    echo -e "${YELLOW}Verifying whitelist configuration...${NC}"
    WHITELIST_CHECK=$(docker exec crowdsec cscli parsers list | grep -i whitelist)
    
    if [[ -n "$WHITELIST_CHECK" ]]; then
        print_success "Whitelist configuration loaded successfully!"
        echo "$WHITELIST_CHECK"
    else
        print_error "Whitelist configuration may not have loaded correctly."
        print_warning "Check CrowdSec logs for more information."
    fi
    
    echo -e "\n${GREEN}Whitelist setup completed.${NC}"
    echo -e "${YELLOW}Note: To modify the whitelist in the future, run this option again.${NC}"
    
    return 0
}

# Function to whitelist current public IP
whitelist_current_ip() {
    print_header "WHITELIST CURRENT PUBLIC IP"
    local ip
    ip=$(get_public_ip)
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    print_info "Your current public IP is: $ip"
    echo -ne "${YELLOW}Whitelist this IP in CrowdSec? (y/n): ${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy] ]]; then
        add_to_crowdsec_whitelist "$ip" || return 1
    fi
    echo -ne "${YELLOW}Whitelist this IP in Traefik? (y/n): ${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy] ]]; then
        add_to_traefik_whitelist "$ip" || return 1
    fi
    print_success "IP whitelisting completed."
    return 0
}

# Function to whitelist a specified IP
whitelist_manual_ip() {
    print_header "WHITELIST A SPECIFIC IP"
    echo -ne "${YELLOW}Enter the IP address to whitelist: ${NC}"
    local ip
    read -r ip
    if ! validate_ip "$ip"; then
        print_error "Invalid IP address format."
        return 1
    fi
    echo -ne "${YELLOW}Whitelist this IP in CrowdSec? (y/n): ${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy] ]]; then
        add_to_crowdsec_whitelist "$ip" || return 1
    fi
    echo -ne "${YELLOW}Whitelist this IP in Traefik? (y/n): ${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy] ]]; then
        add_to_traefik_whitelist "$ip" || return 1
    fi
    print_success "IP whitelisting completed."
    return 0
}

# Function to view whitelisted IPs
view_whitelisted() {
    print_header "CURRENTLY WHITELISTED IPs"
    print_info "CrowdSec Whitelist (includes IP ranges/subnets):"
    if ! check_container "crowdsec"; then
        print_error "Cannot check CrowdSec whitelist."
    else
        local crowdsec_whitelist="/etc/crowdsec/parsers/s02-enrich/whitelists.yaml"
        if ! docker exec crowdsec test -f "$crowdsec_whitelist" 2>/dev/null; then
            print_warning "No CrowdSec whitelist file found."
        else
            docker cp "crowdsec:$crowdsec_whitelist" "${TEMP_DIR}/check_whitelist.yaml" 2>/dev/null
            if [[ -f "${TEMP_DIR}/check_whitelist.yaml" ]]; then
                print_info "IPs and subnets in CrowdSec whitelist:"
                grep -A 50 "ip:" "${TEMP_DIR}/check_whitelist.yaml" | grep -E "^ *-" | 
                sed 's/^ *- *//' | sed 's/["#].*$//' | sed '/^$/d' | sed 's/^[ \t]*//' |
                while read -r line; do
                    echo "  - $line"
                done
                print_info "Note: Entries with /8, /16, /24, etc. are subnets that include multiple IPs"
            else
                print_error "Failed to copy whitelist from CrowdSec container."
            fi
        fi
    fi
    echo ""
    print_info "Traefik Whitelist (includes IP ranges/subnets):"
    if [[ ! -f "$TRAEFIK_CONFIG_PATH" ]]; then
        print_warning "Traefik configuration file not found."
    else
        if grep -q "clientTrustedIPs:" "$TRAEFIK_CONFIG_PATH"; then
            print_info "Client Trusted IPs:"
            grep -A 20 "clientTrustedIPs:" "$TRAEFIK_CONFIG_PATH" | grep -E "^ *- " | 
            sed 's/^ *- *//' | sed 's/ *#.*$//' | sed '/^$/d' |
            while read -r line; do
                echo "  - $line"
            done
        fi
        if grep -q "sourceRange:" "$TRAEFIK_CONFIG_PATH"; then
            print_info "Source Range Whitelist:"
            grep -A 20 "sourceRange:" "$TRAEFIK_CONFIG_PATH" | grep -E "^ *- " | 
            sed 's/^ *- *//' | sed 's/ *#.*$//' | sed '/^$/d' |
            while read -r line; do
                echo "  - $line"
            done
        fi
        if grep -q "forwardedHeadersTrustedIPs:" "$TRAEFIK_CONFIG_PATH"; then
            print_info "Forwarded Headers Trusted IPs:"
            grep -A 20 "forwardedHeadersTrustedIPs:" "$TRAEFIK_CONFIG_PATH" | grep -E "^ *- " | 
            sed 's/^ *- *//' | sed 's/ *#.*$//' | sed '/^$/d' |
            while read -r line; do
                echo "  - $line"
            done
        fi
        print_info "Note: Entries with /8, /16, /24, etc. are subnets that include multiple IPs"
    fi
    return 0
}
