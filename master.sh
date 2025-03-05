#!/bin/bash

# Master script for CrowdSec Manager

# Enable strict error handling
set -o errexit
set -o nounset
set -o pipefail

# Set configurations
CONFIG_DIR="./config"
TRAEFIK_CONFIG_PATH="${CONFIG_DIR}/traefik/dynamic_config.yml"
TEMP_DIR=$(mktemp -d /tmp/crowdsec-manager.XXXXXX)
TEMP_WHITELIST="${TEMP_DIR}/whitelists.yaml"
TEMP_CONFIG="${TEMP_DIR}/dynamic_config.yml"

# Source all scripts
source utils.sh
source decisions.sh
source enrollment.sh
source whitelist.sh
source scenarios.sh
source captcha.sh
source health_checks.sh
source ip_management.sh

# Signal handling
handle_sigint() {
    echo -e "\n${YELLOW}Operation cancelled. Returning to menu...${NC}"
    return 1
}
trap handle_sigint SIGINT

# Check prerequisites
check_prerequisites() {
    print_header "CHECKING PREREQUISITES"
    
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    else
        print_success "Docker is running"
    fi
    
    if ! docker ps -a | grep crowdsec; then
        print_error "CrowdSec container does not exist. Please ensure it's created."
        print_warning "You may need to run your docker-compose first."
        exit 1
    fi
    
    check_container "crowdsec"
    check_container "traefik"
    check_container "pangolin"
    check_container "gerbil"
    
    echo ""
    return 0
}

# Main menu
show_menu() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}   CROWDSEC MANAGER FOR PANGOLIN - ALL-IN-ONE MANAGEMENT TOOL${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
    echo -e "${CYAN}SYSTEM HEALTH & DIAGNOSTICS${NC}"
    echo -e "${CYAN}1.${NC} Check System Health"
    echo -e "${CYAN}2.${NC} Run Complete Diagnostic Check"
    echo -e "${CYAN}3.${NC} Check CrowdSec Bouncers"
    echo -e "${CYAN}4.${NC} Check CrowdSec Metrics"
    echo -e "${CYAN}5.${NC} Check Traefik CrowdSec Integration"
    echo ""
    echo -e "${CYAN}IP MANAGEMENT${NC}"
    echo -e "${CYAN}6.${NC} Check CrowdSec Decisions (List Blocked IPs)"
    echo -e "${CYAN}7.${NC} IP Whitelist Management"
    echo -e "${CYAN}8.${NC} Unban an IP"
    echo -e "${CYAN}9.${NC} Check IP Security Status"
    echo ""
    echo -e "${CYAN}ADVANCED CONFIGURATION${NC}"
    echo -e "${CYAN}10.${NC} Enroll with CrowdSec Console"
    echo -e "${CYAN}11.${NC} Set Up Custom Scenarios"
    echo -e "${CYAN}12.${NC} Set Up Captcha Protection"
    echo ""
    echo -e "${CYAN}LOGS & MONITORING${NC}"
    echo -e "${CYAN}13.${NC} View Recent CrowdSec Logs"
    echo -e "${CYAN}14.${NC} View Recent Traefik Logs"
    echo -e "${CYAN}15.${NC} Follow CrowdSec Logs (Live) - Use Ctrl+C to exit"
    echo ""
    echo -e "${CYAN}0.${NC} Exit"
    echo ""
    echo -ne "${YELLOW}Enter your choice [0-15]:${NC} "
    read -r choice
    
    case $choice in
        1) check_stack_health; press_enter_to_continue ;;
        2) run_complete_check; press_enter_to_continue ;;
        3) check_crowdsec_bouncers; press_enter_to_continue ;;
        4) check_crowdsec_metrics; press_enter_to_continue ;;
        5) check_traefik_crowdsec; press_enter_to_continue ;;
        6) check_crowdsec_decisions; press_enter_to_continue ;;
        7) setup_whitelist; press_enter_to_continue ;;
        8) unban_manual_ip; press_enter_to_continue ;;
        9) check_ip_security; press_enter_to_continue ;;
        10) enroll_crowdsec; press_enter_to_continue ;;
        11) setup_custom_scenarios; press_enter_to_continue ;;
        12) setup_captcha; press_enter_to_continue ;;
        13) analyze_crowdsec_logs; press_enter_to_continue ;;
        14) analyze_traefik_logs; press_enter_to_continue ;;
        15) follow_logs_live "crowdsec"; clear ;;
        0) cleanup; exit 0 ;;
        *) echo -e "${RED}Invalid option. Please try again.${NC}"; press_enter_to_continue ;;
    esac
}

# Entry point
if [[ $EUID -ne 0 && $(docker info >/dev/null 2>&1 || echo $?) ]]; then
    print_error "This script may require elevated permissions to interact with Docker."
    print_warning "Consider running with 'sudo' if you encounter permission issues."
fi

trap cleanup EXIT

check_prerequisites

while true; do
    clear
    show_menu
done
