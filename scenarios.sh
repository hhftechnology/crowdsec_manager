#!/bin/bash

# Function to set up custom scenarios
setup_custom_scenarios() {
    print_header "SETTING UP CUSTOM SCENARIOS"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot set up custom scenarios."
        return 1
    fi
    
    echo -e "${YELLOW}This will install custom scenarios for Pangolin protection.${NC}"
    
    if ! confirm_action "Do you want to proceed?"; then
        echo -e "${YELLOW}Custom scenarios setup canceled.${NC}"
        return 0
    fi
    
    declare -A scenario_files
    scenario_files["pangolin-auth-bruteforce.yaml"]=$(cat << 'EOF'
type: leaky
name: pangolin-auth-bruteforce
description: "Detect authentication bruteforce attempts on Pangolin"
filter: "evt.Meta.log_type == 'http' && evt.Meta.http_path contains '/auth/' && evt.Meta.http_status in ['401', '403']"
groupby: "evt.Meta.source_ip"
capacity: 5
leakspeed: "10m"
blackhole: 15m
labels:
  service: pangolin
  type: bruteforce
  remediation: true
EOF
)

    scenario_files["pangolin-api-abuse.yaml"]=$(cat << 'EOF'
type: leaky
name: pangolin-api-abuse
description: "Detect API abuse on Pangolin"
filter: "evt.Meta.log_type == 'http' && evt.Meta.http_path contains '/api/v1/' && evt.Meta.http_method in ['POST', 'PUT', 'DELETE']"
groupby: "evt.Meta.source_ip"
capacity: 30
leakspeed: "1m"
blackhole: 5m
labels:
  service: pangolin
  type: abuse
  remediation: true
EOF
)

    scenario_files["pangolin-resource-scanning.yaml"]=$(cat << 'EOF'
type: leaky
name: pangolin-resource-scanning
description: "Detect resource enumeration or scanning"
filter: "evt.Meta.log_type == 'http' && evt.Meta.http_status in ['404', '403'] && evt.Meta.http_path contains '.'"
groupby: "evt.Meta.source_ip"
distinct: "evt.Meta.http_path"
capacity: 15
leakspeed: "5m"
blackhole: 10m
labels:
  service: pangolin
  type: scan
  remediation: true
EOF
)

    scenario_files["pangolin-http-flood.yaml"]=$(cat << 'EOF'
type: leaky
name: pangolin-http-flood
description: "Detect HTTP flooding attacks on Pangolin services"
filter: "evt.Meta.log_type == 'http'"
groupby: "evt.Meta.source_ip"
capacity: 100
leakspeed: "10s"
blackhole: 5m
labels:
  service: pangolin
  type: flood
  remediation: true
EOF
)

    for filename in "${!scenario_files[@]}"; do
        echo -e "${YELLOW}Creating $filename...${NC}"
        temp_file="${TEMP_DIR}/$filename"
        echo "${scenario_files[$filename]}" > "$temp_file"
        
        echo -e "${YELLOW}Copying $filename to CrowdSec container...${NC}"
        if ! docker cp "$temp_file" "crowdsec:/etc/crowdsec/scenarios/$filename"; then
            print_error "Failed to copy $filename to CrowdSec container"
            return 1
        fi
        
        print_success "$filename installed successfully"
    done
    
    echo -e "${YELLOW}Restarting CrowdSec to apply scenarios...${NC}"
    if ! docker restart crowdsec; then
        print_error "Failed to restart CrowdSec container"
        return 1
    fi
    
    sleep 5
    
    echo -e "${YELLOW}Verifying custom scenarios...${NC}"
    SCENARIOS_CHECK=$(docker exec crowdsec cscli scenarios list | grep -i pangolin)
    
    if [[ -n "$SCENARIOS_CHECK" ]]; then
        print_success "Custom scenarios loaded successfully!"
        echo "$SCENARIOS_CHECK"
    else
        print_error "Custom scenarios may not have loaded correctly."
        print_warning "Check CrowdSec logs for more information."
    fi
    
    echo -e "\n${GREEN}Custom scenarios setup completed.${NC}"
    
    return 0
}
