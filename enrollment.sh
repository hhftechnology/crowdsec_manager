#!/bin/bash

# Function to enroll CrowdSec with console
enroll_crowdsec() {
    print_header "CROWDSEC CONSOLE ENROLLMENT"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot proceed with enrollment."
        return 1
    fi
    
    echo -e "\n${YELLOW}Please retrieve your enrollment key from ${CYAN}https://app.crowdsec.net${NC}"
    echo -e "${YELLOW}You can find it in your dashboard under 'Connect with the Console' section.${NC}"
    echo -ne "${YELLOW}Please enter your enrollment key:${NC} "
    read -r ENROLL_KEY
    
    if [[ -z "$ENROLL_KEY" ]]; then
        print_error "Enrollment key cannot be empty."
        return 1
    fi
    
    echo -e "\n${YELLOW}Enrolling your CrowdSec instance with the Console...${NC}"
    ENROLL_RESULT=$(docker exec crowdsec cscli console enroll "$ENROLL_KEY" 2>&1) || {
        print_error "Enrollment failed with the following error:"
        echo -e "${RED}$ENROLL_RESULT${NC}"
        return 1
    }
    
    print_success "Enrollment command executed successfully!"
    
    echo -e "\n${YELLOW}Restarting CrowdSec to apply changes...${NC}"
    docker restart crowdsec || {
        print_error "Failed to restart CrowdSec container."
        return 1
    }
    
    sleep 5
    
    if ! docker ps | grep -q "crowdsec"; then
        print_error "CrowdSec container failed to restart."
        return 1
    else
        print_success "CrowdSec restarted successfully!"
    fi
    
    echo -e "\n${YELLOW}IMPORTANT:${NC}"
    echo -e "1. Go to ${CYAN}https://app.crowdsec.net${NC} dashboard"
    echo -e "2. Look for your instance named '${CYAN}pangolin-crowdsec${NC}' (based on your docker-compose)"
    echo -e "3. Accept the instance in your dashboard"
    echo -e "4. Press Enter after accepting the instance to check the status"
    read -r
    
    echo -e "\n${YELLOW}Enabling context forwarding...${NC}"
    docker exec crowdsec cscli console enable context || {
        print_error "Failed to enable context forwarding."
        return 1
    }
    
    print_success "Context forwarding enabled!"
    
    echo -e "\n${YELLOW}Enabling console management...${NC}"
    docker exec crowdsec cscli console enable console_management || {
        print_error "Failed to enable console management."
        return 1
    }
    
    print_success "Console management enabled!"
    
    echo -e "\n${YELLOW}Checking CrowdSec Console status...${NC}"
    CONSOLE_STATUS=$(docker exec crowdsec cscli console status)
    echo -e "${GREEN}Console Status:${NC}"
    echo "$CONSOLE_STATUS"
    
    echo -e "\n${GREEN}===================================================${NC}"
    echo -e "${GREEN}CrowdSec enrollment process completed!${NC}"
    echo -e "${GREEN}===================================================${NC}"
    
    return 0
}
