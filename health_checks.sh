#!/bin/bash

# Function to check container health
check_stack_health() {
    print_header "CHECKING CONTAINER HEALTH"
    
    check_container "crowdsec"
    local crowdsec_running=$?
    
    check_container "traefik"
    local traefik_running=$?
    
    check_container "pangolin"
    local pangolin_running=$?
    
    check_container "gerbil"
    local gerbil_running=$?
    
    echo ""
    
    if [ $crowdsec_running -eq 0 ] && [ $traefik_running -eq 0 ] && [ $pangolin_running -eq 0 ] && [ $gerbil_running -eq 0 ]; then
        print_success "All required containers are running."
    else
        print_error "One or more required containers are not running. Check the Docker logs."
    fi
    
    echo ""
    return 0
}

# Function to check CrowdSec bouncers
check_crowdsec_bouncers() {
    print_header "CHECKING CROWDSEC BOUNCERS"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot check bouncers."
        return 1
    fi
    
    run_command "docker exec crowdsec cscli bouncers list" "Listing registered CrowdSec bouncers"
    
    echo -e "${YELLOW}Verifying Traefik bouncer connection:${NC}"
    if docker exec crowdsec cscli bouncers list | grep -q "traefik"; then
        print_success "Traefik bouncer is registered with CrowdSec"
    else
        print_error "Traefik bouncer is NOT registered with CrowdSec"
        print_warning "Check that the API key in the middleware configuration matches a registered bouncer."
    fi
    
    echo ""
    return 0
}

# Function to check CrowdSec metrics
check_crowdsec_metrics() {
    print_header "CHECKING CROWDSEC METRICS"
    
    # Check if the CrowdSec container is running
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot check metrics."
        return 1
    fi
    
    # Check if curl is installed
    if ! command -v curl &> /dev/null; then
        print_error "curl is not installed. Cannot check metrics."
        echo ""
        return 0  # Return success to continue with other checks
    fi
    
    echo -e "${YELLOW}CrowdSec Prometheus metrics (showing first 10 lines)${NC}"
    echo -e "${CYAN}Command: curl -s http://localhost:6060/metrics | grep crowdsec | head -n 10${NC}"
    echo -e "${CYAN}Output:${NC}"
    
    # Use a temporary file to store curl output
    metrics_temp="${TEMP_DIR}/crowdsec_metrics.txt"
    if curl -s --connect-timeout 5 http://localhost:6060/metrics > "$metrics_temp" 2>/dev/null; then
        # If curl succeeds, check if there's data and filter it
        if [ -s "$metrics_temp" ]; then
            if grep -q crowdsec "$metrics_temp"; then
                grep crowdsec "$metrics_temp" | head -n 10
            else
                echo "No crowdsec metrics found."
            fi
        else
            print_warning "No metrics data retrieved from CrowdSec."
        fi
    else
        # If curl fails, print an error but don't exit the script
        print_error "Failed to retrieve metrics from CrowdSec. Is the metrics endpoint accessible?"
    fi
    
    echo ""
    return 0  # Always return success to continue with other checks
}

# Function to check Traefik CrowdSec integration
check_traefik_crowdsec() {
    print_header "CHECKING TRAEFIK CROWDSEC INTEGRATION"
    
    if ! check_container "traefik"; then
        print_error "Traefik container is not running. Cannot check integration."
        return 1
    fi
    
    echo -e "${YELLOW}Verifying Traefik middleware configuration:${NC}"
    
    found_middleware=0
    
    declare -a config_locations=(
        "./config/traefik/traefik_config.yml"
        "./config/traefik/dynamic_config.yml"
        "./config/traefik/*.yml"
    )
    
    if [ -d "./config/traefik/rules" ]; then
        config_locations+=("./config/traefik/rules/*.yaml" "./config/traefik/rules/*.yml")
    fi
    
    for location in "${config_locations[@]}"; do
        if grep -q "crowdsec" $location 2>/dev/null; then
            print_success "CrowdSec referenced in $location"
            found_middleware=1
        fi
        
        if grep -q "crowdsec@file" $location 2>/dev/null; then
            print_success "CrowdSec middleware (@file) found in $location"
            found_middleware=1
        fi
    done
    
    if [ $found_middleware -eq 0 ]; then
        print_error "CrowdSec middleware not found in Traefik configuration files"
    fi
    
    echo ""
    return 0
}

# Function to run a complete diagnostic check
run_complete_check() {
    check_stack_health
    check_crowdsec_bouncers
    check_crowdsec_decisions
    check_crowdsec_metrics
    check_traefik_crowdsec
    
    print_header "DIAGNOSTIC SUMMARY"
    
    echo -e "${YELLOW}Verifying key configuration settings:${NC}"
    
    lapi_key_found=0
    appsec_enabled=0
    middleware_configured=0
    
    for config_file in $(find ./config -type f -name "*.yml" -o -name "*.yaml" | xargs grep -l "crowdsec" 2>/dev/null); do
        if grep -q "crowdsecLapiKey\|lapiKey\|crowdsecLapi" "$config_file" 2>/dev/null; then
            print_success "CrowdSec LAPI key found in $config_file"
            lapi_key_found=1
        fi
        
        if grep -q "crowdsecAppsecEnabled: *true\|appsecEnabled: *true" "$config_file" 2>/dev/null; then
            print_success "CrowdSec AppSec is enabled in $config_file"
            appsec_enabled=1
        fi
        
        if grep -q "middleware.*crowdsec\|crowdsec.*middleware\|crowdsec@file\|crowdsec:" "$config_file" 2>/dev/null; then
            print_success "CrowdSec middleware configured in $config_file"
            middleware_configured=1
        fi
    done
    
    if [ $lapi_key_found -eq 0 ]; then
        print_error "No CrowdSec LAPI key found in configuration files"
    fi
    
    if [ $appsec_enabled -eq 0 ]; then
        print_warning "CrowdSec AppSec not explicitly enabled in configuration files"
    fi
    
    if [ $middleware_configured -eq 0 ]; then
        print_error "CrowdSec middleware not properly configured in Traefik"
    fi
    
    echo ""
    echo -e "${YELLOW}=== FINAL VERDICT ===${NC}"
    
    if check_container "crowdsec" > /dev/null && \
       ([ $lapi_key_found -eq 1 ] || [ $middleware_configured -eq 1 ]); then
        print_success "CrowdSec appears to be working correctly."
    else
        print_warning "CrowdSec may not be functioning properly. Review the diagnostics above."
    fi
    
    echo ""
    press_enter_to_continue
    return 0
}

# Function to analyze Traefik logs
analyze_traefik_logs() {
    print_header "ANALYZE TRAEFIK ACCESS LOGS"
    if ! check_container "traefik"; then
        print_error "Traefik container is not running. Cannot check logs."
        return 1
    fi
    
    print_info "Extracting recent logs from Traefik..."
    echo ""
    
    local logs
    logs=$(docker logs traefik 2>&1 | tail -n 50)
    
    if [[ -z "$logs" ]]; then
        print_warning "No logs found for Traefik container."
    else
        if echo "$logs" | grep -q -i "access"; then
            print_info "Found access logs:"
            echo "$logs" | grep -i "access"
        else
            print_info "No specific access logs found. Showing recent logs:"
            echo "$logs"
        fi
    fi
    
    echo ""
    return 0
}

# Function to analyze CrowdSec logs
analyze_crowdsec_logs() {
    print_header "ANALYZE CROWDSEC LOGS"
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot check logs."
        return 1
    fi
    print_info "Extracting recent logs from CrowdSec..."
    ( docker logs crowdsec 2>&1 | tail -n 50 ) || true
    
    return 0
}

# Function to check logs
check_logs() {
    local service=$1
    local follow=${2:-"false"}
    
    local cmd
    if [ -z "$service" ]; then
        cmd="docker compose logs --tail=50"
        print_header "SHOWING LOGS FOR ALL SERVICES"
    else
        cmd="docker compose logs $service --tail=50"
        print_header "SHOWING LOGS FOR $service"
    fi
    
    if [ "$follow" = "true" ]; then
        cmd="$cmd -f"
    fi
    
    echo -e "${YELLOW}Running: $cmd${NC}"
    if [ "$follow" = "true" ]; then
        echo -e "${YELLOW}Press Ctrl+C to exit log view${NC}"
    fi
    echo ""
    
    eval "$cmd"
    
    if [ "$follow" != "true" ]; then
        press_enter_to_continue
    fi
}

# Function to follow logs in live mode
follow_logs_live() {
    local service=$1
    
    print_header "FOLLOWING ${service^^} LOGS (LIVE)"
    echo -e "${YELLOW}Press Ctrl+C to exit and return to menu${NC}"
    echo ""
    
    docker compose logs "$service" -f &
    
    LOGS_PID=$!
    
    trap "kill $LOGS_PID 2>/dev/null; echo -e '\n${YELLOW}Returning to menu...${NC}'; sleep 1; return 0" SIGINT
    
    wait $LOGS_PID
    
    trap handle_sigint SIGINT
    
    return 0
}