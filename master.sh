#!/usr/bin/env bash

# Enable xtrace if the DEBUG environment variable is set
if [[ ${DEBUG-} =~ ^1|yes|true$ ]]; then
    set -o xtrace       # Trace the execution of the script (debug)
fi

# Only enable these shell behaviours if we're not being sourced
# Approach via: https://stackoverflow.com/a/28776166/8787985
if ! (return 0 2> /dev/null); then
    # A better class of script...
    set -o errexit      # Exit on most errors (see the manual)
    set -o nounset      # Disallow expansion of unset variables
    set -o pipefail     # Use last non-zero exit code in a pipeline
fi

# Enable errtrace or the error trap handler will not work as expected
set -o errtrace         # Ensure the error trap handler is inherited

# Set configurations
CONFIG_DIR="./config"
TRAEFIK_CONFIG_PATH="${CONFIG_DIR}/traefik/dynamic_config.yml"
TEMP_DIR=$(mktemp -d /tmp/crowdsec-manager.XXXXXX)
TEMP_WHITELIST="${TEMP_DIR}/whitelists.yaml"
TEMP_CONFIG="${TEMP_DIR}/dynamic_config.yml"
CROWDSEC_WHITELIST_PATH="/etc/crowdsec/parsers/s02-enrich/whitelists.yaml"

# Backup and update configurations
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_BACKUP_DIR="${SCRIPT_DIR}/backups"
DEFAULT_CONFIG_FILE="${SCRIPT_DIR}/.pangolin-backup.conf"
DEFAULT_RETENTION_DAYS=60
DEFAULT_BACKUP_ITEMS=("docker-compose.yml" "config")
BACKUP_DIR="${DEFAULT_BACKUP_DIR}"
RETENTION_DAYS="${DEFAULT_RETENTION_DAYS}"
BACKUP_ITEMS=("${DEFAULT_BACKUP_ITEMS[@]}")
BACKUP_TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
PANGOLIN_DIR="${SCRIPT_DIR}"
DOCKER_COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
DRY_RUN=false
INCLUDE_CROWDSEC=true
LOG_FILE="${BACKUP_DIR}/pangolin-backup.log"
OPERATION_CANCELLED=false

# Service definitions
SERVICES_BASIC=("pangolin" "gerbil" "traefik")
SERVICES_WITH_CROWDSEC=("pangolin" "gerbil" "crowdsec" "traefik")
SERVICES=("${SERVICES_WITH_CROWDSEC[@]}")

# Terminal colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Calculate the width of the header
HEADER_WIDTH=80  # Adjust as needed

# Create the header lines
HEADER_LINE="${CYAN}================================================================================${NC}"

# Create the title line with centered text and stars
TITLE="CROWDSEC MANAGER FOR PANGOLIN - ALL-IN-ONE MANAGEMENT TOOL"
PADDING=$(( (HEADER_WIDTH - ${#TITLE}) / 2 )) #calculate padding for centered text, -4 for the stars
TITLE_LINE="${CYAN}$(printf "%${PADDING}s" "")${TITLE}$(printf "%${PADDING}s" "")${NC}"

# Create the author line with centered text and dashes
AUTHOR="by hhf-technology https://forums.hhf.technology"
PADDING_AUTHOR=$(( (HEADER_WIDTH - ${#AUTHOR}) / 2 )) #calculate padding for centered text, -2 for the dashes
AUTHOR_LINE="${CYAN}$(printf "%${PADDING_AUTHOR}s" "")${AUTHOR}$(printf "%${PADDING_AUTHOR}s" "")${NC}"


# DESC: Handler for unexpected errors
# ARGS: $1 (optional): Exit code (defaults to 1)
# OUTS: None
# RETS: None
function script_trap_err() {
    local exit_code=1

    # Disable the error trap handler to prevent potential recursion
    trap - ERR

    # Consider any further errors non-fatal to ensure we run to completion
    set +o errexit
    set +o pipefail

    # Validate any provided exit code
    if [[ ${1-} =~ ^[0-9]+$ ]]; then
        exit_code="$1"
    fi
    # Only exit if this is a fatal error (modify this condition as needed)
    if [[ $exit_code -gt 1 ]]; then
    # Output debug data if in Cron mode
    if [[ -n ${cron-} ]]; then
        # Restore original file output descriptors
        if [[ -n ${script_output-} ]]; then
            exec 1>&3 2>&4
        fi
    
        # Print basic debugging information
        printf '%b\n' "$ta_none"
        printf '***** Abnormal termination of script *****\n'
        printf 'Script Path:            %s\n' "$script_path"
        printf 'Script Parameters:      %s\n' "$script_params"
        printf 'Script Exit Code:       %s\n' "$exit_code"

        # Print the script log if we have it. It's possible we may not if we
        # failed before we even called cron_init(). This can happen if bad
        # parameters were passed to the script so we bailed out very early.
        if [[ -n ${script_output-} ]]; then
            # shellcheck disable=SC2312
            printf 'Script Output:\n\n%s' "$(cat "$script_output")"
        else
            printf 'Script Output:          None (failed before log init)\n'
        fi
    fi

    # Exit with failure status
    exit "$exit_code"
    fi
    # For non-fatal errors, just log the error and continue
    log "ERROR" "An error occurred but execution will continue"
}

# DESC: Handler for exiting the script
# ARGS: None
# OUTS: None
# RETS: None
function script_trap_exit() {
    cd "$orig_cwd"

    # Remove Cron mode script log
    if [[ -n ${cron-} && -f ${script_output-} ]]; then
        rm "$script_output"
    fi

    # Remove script execution lock
    if [[ -d ${script_lock-} ]]; then
        rmdir "$script_lock"
    fi

    # Restore terminal colours
    printf '%b' "$ta_none"
    
    # Clean up temp files
    cleanup
}

# DESC: Exit script with the given message
# ARGS: $1 (required): Message to print on exit
#       $2 (optional): Exit code (defaults to 0)
# OUTS: None
# RETS: None
# NOTE: The convention used in this script for exit codes is:
#       0: Normal exit
#       1: Abnormal exit due to external error
#       2: Abnormal exit due to script error
function script_exit() {
    if [[ $# -eq 1 ]]; then
        printf '%s\n' "$1"
        exit 0
    fi

    if [[ ${2-} =~ ^[0-9]+$ ]]; then
        printf '%b\n' "$1"
        # If we've been provided a non-zero exit code run the error trap
        if [[ $2 -ne 0 ]]; then
            script_trap_err "$2"
        else
            exit 0
        fi
    fi

    script_exit 'Missing required argument to script_exit()!' 2
}

# DESC: Generic script initialisation
# ARGS: $@ (optional): Arguments provided to the script
# OUTS: $orig_cwd: The current working directory when the script was run
#       $script_path: The full path to the script
#       $script_dir: The directory path of the script
#       $script_name: The file name of the script
#       $script_params: The original parameters provided to the script
#       $ta_none: The ANSI control code to reset all text attributes
# RETS: None
# NOTE: $script_path only contains the path that was used to call the script
#       and will not resolve any symlinks which may be present in the path.
#       You can use a tool like realpath to obtain the "true" path. The same
#       caveat applies to both the $script_dir and $script_name variables.
# shellcheck disable=SC2034
function script_init() {
    # Useful variables
    readonly orig_cwd="$PWD"
    readonly script_params="$*"
    readonly script_path="${BASH_SOURCE[0]}"
    script_dir="$(dirname "$script_path")"
    script_name="$(basename "$script_path")"
    readonly script_dir script_name

    # Important to always set as we use it in the exit handler
    # shellcheck disable=SC2155
    readonly ta_none="$(tput sgr0 2> /dev/null || true)"
}

# DESC: Initialise colour variables
# ARGS: None
# OUTS: Read-only variables with ANSI control codes
# RETS: None
# NOTE: If --no-colour was set the variables will be empty. The output of the
#       $ta_none variable after each tput is redundant during normal execution,
#       but ensures the terminal output isn't mangled when running with xtrace.
# shellcheck disable=SC2034,SC2155
function colour_init() {
    if [[ -z ${no_colour-} ]]; then
        # Text attributes
        readonly ta_bold="$(tput bold 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly ta_uscore="$(tput smul 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly ta_blink="$(tput blink 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly ta_reverse="$(tput rev 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly ta_conceal="$(tput invis 2> /dev/null || true)"
        printf '%b' "$ta_none"

        # Foreground codes
        readonly fg_black="$(tput setaf 0 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly fg_blue="$(tput setaf 4 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly fg_cyan="$(tput setaf 6 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly fg_green="$(tput setaf 2 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly fg_magenta="$(tput setaf 5 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly fg_red="$(tput setaf 1 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly fg_white="$(tput setaf 7 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly fg_yellow="$(tput setaf 3 2> /dev/null || true)"
        printf '%b' "$ta_none"

        # Background codes
        readonly bg_black="$(tput setab 0 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly bg_blue="$(tput setab 4 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly bg_cyan="$(tput setab 6 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly bg_green="$(tput setab 2 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly bg_magenta="$(tput setab 5 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly bg_red="$(tput setab 1 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly bg_white="$(tput setab 7 2> /dev/null || true)"
        printf '%b' "$ta_none"
        readonly bg_yellow="$(tput setab 3 2> /dev/null || true)"
        printf '%b' "$ta_none"
    else
        # Text attributes
        readonly ta_bold=''
        readonly ta_uscore=''
        readonly ta_blink=''
        readonly ta_reverse=''
        readonly ta_conceal=''

        # Foreground codes
        readonly fg_black=''
        readonly fg_blue=''
        readonly fg_cyan=''
        readonly fg_green=''
        readonly fg_magenta=''
        readonly fg_red=''
        readonly fg_white=''
        readonly fg_yellow=''

        # Background codes
        readonly bg_black=''
        readonly bg_blue=''
        readonly bg_cyan=''
        readonly bg_green=''
        readonly bg_magenta=''
        readonly bg_red=''
        readonly bg_white=''
        readonly bg_yellow=''
    fi
}

# DESC: Initialise Cron mode
# ARGS: None
# OUTS: $script_output: Path to the file stdout & stderr was redirected to
# RETS: None
function cron_init() {
    if [[ -n ${cron-} ]]; then
        # Redirect all output to a temporary file
        script_output="$(mktemp --tmpdir "$script_name".XXXXX)"
        readonly script_output
        exec 3>&1 4>&2 1> "$script_output" 2>&1
    fi
}

# DESC: Acquire script lock
# ARGS: $1 (optional): Scope of script execution lock (system or user)
# OUTS: $script_lock: Path to the directory indicating we have the script lock
# RETS: None
# NOTE: This lock implementation is extremely simple but should be reliable
#       across all platforms. It does *not* support locking a script with
#       symlinks or multiple hardlinks as there's no portable way of doing so.
#       If the lock was acquired it's automatically released on script exit.
function lock_init() {
    local lock_dir
    if [[ $1 = 'system' ]]; then
        lock_dir="/tmp/$script_name.lock"
    elif [[ $1 = 'user' ]]; then
        lock_dir="/tmp/$script_name.$UID.lock"
    else
        script_exit 'Missing or invalid argument to lock_init()!' 2
    fi

    if mkdir "$lock_dir" 2> /dev/null; then
        readonly script_lock="$lock_dir"
        verbose_print "Acquired script lock: $script_lock"
    else
        script_exit "Unable to acquire script lock: $lock_dir" 1
    fi
}

# DESC: Pretty print the provided string
# ARGS: $1 (required): Message to print (defaults to a green foreground)
#       $2 (optional): Colour to print the message with. This can be an ANSI
#                      escape code or one of the prepopulated colour variables.
#       $3 (optional): Set to any value to not append a new line to the message
# OUTS: None
# RETS: None
function pretty_print() {
    if [[ $# -lt 1 ]]; then
        script_exit 'Missing required argument to pretty_print()!' 2
    fi

    if [[ -z ${no_colour-} ]]; then
        if [[ -n ${2-} ]]; then
            printf '%b' "$2"
        else
            printf '%b' "$fg_green"
        fi
    fi

    # Print message & reset text attributes
    if [[ -n ${3-} ]]; then
        printf '%s%b' "$1" "$ta_none"
    else
        printf '%s%b\n' "$1" "$ta_none"
    fi
}

# DESC: Only pretty_print() the provided string if verbose mode is enabled
# ARGS: $@ (required): Passed through to pretty_print() function
# OUTS: None
# RETS: None
function verbose_print() {
    if [[ -n ${verbose-} ]]; then
        pretty_print "$@"
    fi
}

# DESC: Combines two path variables and removes any duplicates
# ARGS: $1 (required): Path(s) to join with the second argument
#       $2 (optional): Path(s) to join with the first argument
# OUTS: $build_path: The constructed path
# RETS: None
# NOTE: Heavily inspired by: https://unix.stackexchange.com/a/40973
function build_path() {
    if [[ $# -lt 1 ]]; then
        script_exit 'Missing required argument to build_path()!' 2
    fi

    local new_path path_entry temp_path

    temp_path="$1:"
    if [[ -n ${2-} ]]; then
        temp_path="$temp_path$2:"
    fi

    new_path=
    while [[ -n $temp_path ]]; do
        path_entry="${temp_path%%:*}"
        case "$new_path:" in
            *:"$path_entry":*) ;;
            *)
                new_path="$new_path:$path_entry"
                ;;
        esac
        temp_path="${temp_path#*:}"
    done

    # shellcheck disable=SC2034
    build_path="${new_path#:}"
}

# DESC: Check a binary exists in the search path
# ARGS: $1 (required): Name of the binary to test for existence
#       $2 (optional): Set to any value to treat failure as a fatal error
# OUTS: None
# RETS: 0 (true) if dependency was found, otherwise 1 (false) if failure is not
#       being treated as a fatal error.
function check_binary() {
    if [[ $# -lt 1 ]]; then
        script_exit 'Missing required argument to check_binary()!' 2
    fi

    if ! command -v "$1" > /dev/null 2>&1; then
        if [[ -n ${2-} ]]; then
            script_exit "Missing dependency: Couldn't locate $1." 1
        else
            verbose_print "Missing dependency: $1" "${fg_red-}"
            return 1
        fi
    fi

    verbose_print "Found dependency: $1"
    return 0
}

# DESC: Validate we have superuser access as root (via sudo if requested)
# ARGS: $1 (optional): Set to any value to not attempt root access via sudo
# OUTS: None
# RETS: 0 (true) if superuser credentials were acquired, otherwise 1 (false)
function check_superuser() {
    local superuser
    if [[ $EUID -eq 0 ]]; then
        superuser=true
    elif [[ -z ${1-} ]]; then
        # shellcheck disable=SC2310
        if check_binary sudo; then
            verbose_print 'Sudo: Updating cached credentials ...'
            if ! sudo -v; then
                verbose_print "Sudo: Couldn't acquire credentials ..." \
                    "${fg_red-}"
            else
                local test_euid
                test_euid="$(sudo -H -- "$BASH" -c 'printf "%s" "$EUID"')"
                if [[ $test_euid -eq 0 ]]; then
                    superuser=true
                fi
            fi
        fi
    fi

    if [[ -z ${superuser-} ]]; then
        verbose_print 'Unable to acquire superuser credentials.' "${fg_red-}"
        return 1
    fi

    verbose_print 'Successfully acquired superuser credentials.'
    return 0
}

# DESC: Run the requested command as root (via sudo if requested)
# ARGS: $1 (optional): Set to zero to not attempt execution via sudo
#       $@ (required): Passed through for execution as root user
# OUTS: None
# RETS: None
function run_as_root() {
    if [[ $# -eq 0 ]]; then
        script_exit 'Missing required argument to run_as_root()!' 2
    fi

    if [[ ${1-} =~ ^0$ ]]; then
        local skip_sudo=true
        shift
    fi

    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif [[ -z ${skip_sudo-} ]]; then
        sudo -H -- "$@"
    else
        script_exit "Unable to run requested command as root: $*" 1
    fi
}

# DESC: Usage help
# ARGS: None
# OUTS: None
# RETS: None
function script_usage() {
    cat << EOF
Usage:
     -h|--help                  Displays this help
     -v|--verbose               Displays verbose output
    -nc|--no-colour             Disables colour output
    -cr|--cron                  Run silently unless we encounter an error
EOF
}

# DESC: Parameter parser
# ARGS: $@ (optional): Arguments provided to the script
# OUTS: Variables indicating command-line parameters and options
# RETS: None
function parse_params() {
    local param
    while [[ $# -gt 0 ]]; do
        param="$1"
        shift
        case $param in
            -h | --help)
                script_usage
                exit 0
                ;;
            -v | --verbose)
                verbose=true
                ;;
            -nc | --no-colour)
                no_colour=true
                ;;
            -cr | --cron)
                cron=true
                ;;
            *)
                script_exit "Invalid parameter was provided: $param" 1
                ;;
        esac
    done
}

# DESC: Main control flow
# ARGS: $@ (optional): Arguments provided to the script
# OUTS: None
# RETS: None
function main() {
    trap script_trap_err ERR
    trap script_trap_exit EXIT

    script_init "$@"
    parse_params "$@"
    cron_init
    colour_init
    #lock_init system
    
    check_prerequisites
    
    while true; do
        clear
        show_menu
    done
}

########################
# UTILITY FUNCTIONS
########################

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

# Function to print banner
print_banner() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "${CYAN}   $1${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo ""
}

# Log messages to file and console
log() {
    local level="$1"
    local message="$2"
    local timestamp="$(date +"%Y-%m-%d %H:%M:%S")"
    
    if [[ -n "${LOG_FILE}" ]]; then
        mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null || true
        printf "[%s] [%s] %s\n" "${timestamp}" "${level}" "${message}" >> "${LOG_FILE}" 2>/dev/null || true
    fi
    
    case "${level}" in
        "ERROR") print_error "${message}" ;;
        "WARNING") print_warning "${message}" ;;
        "SUCCESS") print_success "${message}" ;;
        "INFO") print_info "${message}" ;;
        *) printf "[%s] %s\n" "${level}" "${message}" ;;
    esac
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

# Signal handling
handle_sigint() {
    echo -e "\n${YELLOW}Operation cancelled. Returning to menu...${NC}"
    return 1
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    for cmd in docker tar grep awk sed; do
        command -v "${cmd}" >/dev/null 2>&1 || missing_deps+=("${cmd}")
    done
    
    if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        missing_deps+=("docker-compose")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        printf "${RED}ERROR: Missing required dependencies: %s${NC}\n" "${missing_deps[*]}" >&2
        return 1
    fi
    return 0
}

# Execute docker compose commands
docker_compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "${DOCKER_COMPOSE_FILE}" "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "${DOCKER_COMPOSE_FILE}" "$@"
    else
        log "ERROR" "Neither 'docker compose' nor 'docker-compose' is available"
        return 1
    fi
}

# Cleanup and exit
cleanup_and_exit() {
    local exit_code=$?
    
    if [[ -n "${temp_dir:-}" && -d "${temp_dir}" ]]; then
        rm -rf "${temp_dir}" 2>/dev/null || true
        log "INFO" "Cleaned up temporary directory: ${temp_dir}"
    fi
    
    if [[ ${exit_code} -ne 0 && "${OPERATION_CANCELLED:-false}" != "true" ]]; then
        if [[ "${FUNCNAME[1]}" != "list_backups" && 
              "${FUNCNAME[1]}" != "delete_backups" && 
              "${FUNCNAME[1]}" != "restore_backup" ]]; then
            printf "\n${YELLOW}Script was interrupted or encountered an error.${NC}\n"
            printf "Exiting with code ${exit_code}\n"
        fi
    fi
    
    exit ${exit_code}
}

########################
# DECISION FUNCTIONS
########################

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

########################
# ENROLLMENT FUNCTIONS
########################

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

########################
# WHITELIST FUNCTIONS
########################
# Validate CIDR notation
validate_cidr() {
    local cidr="$1"
    if [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip=${cidr%/*}
        local prefix=${cidr#*/}
        if validate_ip "$ip" && [[ $prefix -ge 0 && $prefix -le 32 ]]; then
            return 0
        fi
    fi
    return 1
}

# Function to add IP to CrowdSec whitelist
add_to_crowdsec_whitelist() {
    local ip="$1"
    local is_cidr=false
    [[ "$ip" == */* ]] && is_cidr=true
    local whitelist_path="/etc/crowdsec/parsers/s02-enrich/whitelists.yaml"
    
    print_info "Adding IP $ip to CrowdSec whitelist..."

    # Create a temporary file for our new whitelist
    local temp_whitelist="${TEMP_DIR}/new_whitelist.yaml"
    
    if docker exec crowdsec test -f "$whitelist_path" 2>/dev/null; then
        print_info "Existing whitelist found, checking if IP is already whitelisted..."
        docker cp "crowdsec:$whitelist_path" "${TEMP_DIR}/current_whitelist.yaml" 2>/dev/null
        
        if [[ -f "${TEMP_DIR}/current_whitelist.yaml" ]]; then
            # Check if IP is already whitelisted
            if grep -F "\"$ip\"" "${TEMP_DIR}/current_whitelist.yaml" > /dev/null 2>&1 || 
               grep -F "- \"$ip\"" "${TEMP_DIR}/current_whitelist.yaml" > /dev/null 2>&1 || 
               grep -F "- $ip" "${TEMP_DIR}/current_whitelist.yaml" > /dev/null 2>&1; then
                print_info "IP $ip is already whitelisted in CrowdSec."
                rm -f "${TEMP_DIR}/current_whitelist.yaml"
                return 0
            fi
            
            # Copy the file header and metadata
            sed -n '1,/whitelist:/p' "${TEMP_DIR}/current_whitelist.yaml" > "$temp_whitelist"
            
            # Get the whitelist reason
            grep "^  reason:" "${TEMP_DIR}/current_whitelist.yaml" >> "$temp_whitelist" || echo "  reason: \"trusted sources\"" >> "$temp_whitelist"
            
            # Handle IP section
            echo "  ip:" >> "$temp_whitelist"
            
            # Add the new IP if it's not a CIDR
            if [[ "$is_cidr" == "false" ]]; then
                echo "    - \"$ip\"  # Added by CrowdSec Manager" >> "$temp_whitelist"
            fi
            
            # Add existing IPs (except for expressions or CIDRs)
            if grep -q "^  ip:" "${TEMP_DIR}/current_whitelist.yaml"; then
                grep -A 100 "^  ip:" "${TEMP_DIR}/current_whitelist.yaml" | 
                grep "^    - " | 
                grep -v "evt.Parsed" | 
                grep -v "/" >> "$temp_whitelist" || true
            fi
            
            # Make sure localhost is included
            if ! grep -q "127.0.0.1" "$temp_whitelist"; then
                echo "    - \"127.0.0.1\"" >> "$temp_whitelist"
            fi
            
            # Handle CIDR section
            echo "  cidr:" >> "$temp_whitelist"
            
            # Add the new IP if it's a CIDR
            if [[ "$is_cidr" == "true" ]]; then
                echo "    - \"$ip\"  # Added by CrowdSec Manager" >> "$temp_whitelist"
            fi
            
            # Add existing CIDRs
            if grep -q "^  cidr:" "${TEMP_DIR}/current_whitelist.yaml"; then
                grep -A 100 "^  cidr:" "${TEMP_DIR}/current_whitelist.yaml" | 
                grep "^    - " | 
                grep -v "evt.Parsed" | 
                grep "/" >> "$temp_whitelist" || true
            else
                # Add default private network CIDRs if not found
                echo "    - \"10.0.0.0/8\"      # Private network" >> "$temp_whitelist"
                echo "    - \"172.16.0.0/12\"   # Private network" >> "$temp_whitelist"
                echo "    - \"192.168.0.0/16\"  # Private network" >> "$temp_whitelist"
            fi
            
            # Handle expression section
            echo "  expression:" >> "$temp_whitelist"
            
            # Add expressions from the original file
            if grep -q "^  expression:" "${TEMP_DIR}/current_whitelist.yaml"; then
                grep -A 100 "^  expression:" "${TEMP_DIR}/current_whitelist.yaml" | 
                grep "^    - " >> "$temp_whitelist" || true
            else
                # Add default expressions
                echo "    - evt.Parsed.source_ip == '127.0.0.1'" >> "$temp_whitelist"
                echo "    - evt.Parsed.source_ip contains '172.17.' # Docker default network" >> "$temp_whitelist"
            fi
            
        else
            print_info "Could not copy existing whitelist, creating new one..."
            create_default_whitelist "$temp_whitelist" "$ip" "$is_cidr"
        fi
    else
        print_info "No existing whitelist found, creating new one..."
        create_default_whitelist "$temp_whitelist" "$ip" "$is_cidr"
    fi

    # Deploy the new whitelist
    if ! docker cp "$temp_whitelist" "crowdsec:$whitelist_path"; then
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

# Helper function to create a default whitelist
create_default_whitelist() {
    local output_file="$1"
    local ip="$2"
    local is_cidr="$3"
    
    cat > "$output_file" << EOF
---
name: crowdsecurity/whitelists
description: "Whitelist configuration for trusted IPs and networks"
whitelist:
  reason: "trusted sources"
  ip:
EOF

    if [[ "$is_cidr" == "false" ]]; then
        echo "    - \"$ip\"  # Added by CrowdSec Manager" >> "$output_file"
    fi
    
    echo "    - \"127.0.0.1\"" >> "$output_file"
    echo "  cidr:" >> "$output_file"
    
    if [[ "$is_cidr" == "true" ]]; then
        echo "    - \"$ip\"  # Added by CrowdSec Manager" >> "$output_file"
    fi
    
    cat >> "$output_file" << EOF
    - "10.0.0.0/8"      # Private network
    - "172.16.0.0/12"   # Private network
    - "192.168.0.0/16"  # Private network
  expression:
    - evt.Parsed.source_ip == '127.0.0.1'
    - evt.Parsed.source_ip contains '172.17.' # Docker default network
EOF
}


# Function to add IP to Traefik whitelist
# Enhanced function to add IP to Traefik whitelist
add_to_traefik_whitelist() {
    local ip="$1"
    print_info "Adding IP $ip to Traefik whitelist..."
    if [[ ! -f "$TRAEFIK_CONFIG_PATH" ]]; then
        print_error "Traefik configuration file not found at $TRAEFIK_CONFIG_PATH"
        return 1
    fi

    # Check if the IP is already whitelisted
    if grep -F "- $ip" "$TRAEFIK_CONFIG_PATH" > /dev/null 2>&1; then
        print_info "IP $ip is already whitelisted in Traefik configuration."
        return 0
    fi

    # Create backup of Traefik config
    cp "$TRAEFIK_CONFIG_PATH" "${TRAEFIK_CONFIG_PATH}.backup.$(date +%Y%m%d%H%M%S)"
    cp "$TRAEFIK_CONFIG_PATH" "$TEMP_CONFIG"
    local updated=0

    # Update clientTrustedIPs if it exists
    if grep -q "clientTrustedIPs:" "$TEMP_CONFIG"; then
        print_info "Updating clientTrustedIPs section..."
        if grep -F "- $ip" "$TEMP_CONFIG" > /dev/null 2>&1; then
            print_warning "IP $ip is already in clientTrustedIPs"
        else
            sed -i "/clientTrustedIPs:/,/[^-]/s/^      - .*$/&\n      - $ip  # Added by CrowdSec Manager/" "$TEMP_CONFIG"
            updated=1
        fi
    fi

    # Update sourceRange if it exists
    if grep -q "sourceRange:" "$TEMP_CONFIG"; then
        print_info "Updating sourceRange section..."
        if grep -F "- $ip" "$TEMP_CONFIG" > /dev/null 2>&1; then
            print_warning "IP $ip is already in sourceRange"
        else
            sed -i "/sourceRange:/,/[^-]/s/^      - .*$/&\n      - $ip  # Added by CrowdSec Manager/" "$TEMP_CONFIG"
            updated=1
        fi
    fi

    # Update forwardedHeadersTrustedIPs if it exists
    if grep -q "forwardedHeadersTrustedIPs:" "$TEMP_CONFIG"; then
        print_info "Updating forwardedHeadersTrustedIPs section..."
        if grep -F "- $ip" "$TEMP_CONFIG" > /dev/null 2>&1; then
            print_warning "IP $ip is already in forwardedHeadersTrustedIPs"
        else
            sed -i "/forwardedHeadersTrustedIPs:/,/[^-]/s/^      - .*$/&\n      - $ip  # Added by CrowdSec Manager/" "$TEMP_CONFIG"
            updated=1
        fi
    fi

    if [[ $updated -eq 0 ]]; then
        print_warning "No changes made to Traefik configuration. IP may already be whitelisted or sections not found."
        return 0
    fi

    cp "$TEMP_CONFIG" "$TRAEFIK_CONFIG_PATH"
    print_info "Restarting Traefik to apply changes..."
    if ! docker restart traefik; then
        print_error "Failed to restart Traefik. Restoring backup..."
        find "${TRAEFIK_CONFIG_PATH}.backup.*" -type f -exec ls -t {} \; | head -n 1 | xargs -I{} cp {} "$TRAEFIK_CONFIG_PATH"
        return 1
    fi
    sleep 2
    if ! check_container "traefik"; then
        print_error "Traefik container failed to restart. Restoring backup..."
        find "${TRAEFIK_CONFIG_PATH}.backup.*" -type f -exec ls -t {} \; | head -n 1 | xargs -I{} cp {} "$TRAEFIK_CONFIG_PATH"
        docker restart traefik
        return 1
    fi
    print_success "IP $ip has been added to the Traefik whitelist."
    return 0
}

# Function to set up IP whitelisting
# Enhanced function to set up IP whitelisting
setup_whitelist() {
    print_header "SETTING UP IP WHITELISTING"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot set up whitelist."
        return 1
    fi

    echo -e "${CYAN}Select a whitelisting option:${NC}"
    echo -e "${CYAN}1.${NC} Whitelist current public IP"
    echo -e "${CYAN}2.${NC} Whitelist a specific IP"
    echo -e "${CYAN}3.${NC} Whitelist a CIDR range"
    echo -e "${CYAN}4.${NC} Set up comprehensive whitelist with standard private networks"
    echo -e "${CYAN}5.${NC} View currently whitelisted IPs"
    echo -e "${CYAN}0.${NC} Return to main menu"
    echo -ne "${YELLOW}Enter your choice [0-5]:${NC} "
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
            whitelist_cidr_range
            return $?
            ;;
        4)
            setup_comprehensive_whitelist
            return $?
            ;;
        5)
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
}
# Function to whitelist a CIDR range
whitelist_cidr_range() {
    print_header "WHITELIST CIDR RANGE"
    
    echo -ne "${YELLOW}Enter the CIDR range to whitelist (e.g., 192.168.1.0/24): ${NC}"
    local cidr
    read -r cidr
    
    if ! validate_cidr "$cidr"; then
        print_error "Invalid CIDR notation. Format should be like 192.168.1.0/24"
        return 1
    fi
    
    echo -ne "${YELLOW}Whitelist this CIDR range in CrowdSec? (y/n): ${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy] ]]; then
        add_to_crowdsec_whitelist "$cidr" || return 1
    fi
    
    # Note: Traefik supports CIDR notation directly
    echo -ne "${YELLOW}Whitelist this CIDR range in Traefik? (y/n): ${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy] ]]; then
        add_to_traefik_whitelist "$cidr" || return 1
    fi
    
    print_success "CIDR range whitelisting completed."
    return 0
}

# Function to set up comprehensive whitelist
setup_comprehensive_whitelist() {
    print_header "SETTING UP COMPREHENSIVE WHITELIST"
    
    echo -e "${YELLOW}This will set up a comprehensive whitelist with standard private networks.${NC}"
    echo -e "${YELLOW}This includes:${NC}"
    echo -e "  - 127.0.0.1 (localhost)"
    echo -e "  - 10.0.0.0/8 (Private network)"
    echo -e "  - 172.16.0.0/12 (Private network)"
    echo -e "  - 192.168.0.0/16 (Private network)"
    echo -e "  - Your current public IP (optional)"
    
    echo -ne "${YELLOW}Do you want to proceed? (y/n): ${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy] ]]; then
        print_info "Operation cancelled."
        return 0
    fi
    
    # Create temporary whitelist file
    local whitelist_file="${TEMP_DIR}/comprehensive_whitelist.yaml"
    cat > "$whitelist_file" << EOF
---
name: crowdsecurity/whitelists
description: "Comprehensive whitelist configuration for trusted IPs and networks"
whitelist:
  reason: "trusted sources"
  ip:
    - "127.0.0.1"
  cidr:
    - "10.0.0.0/8"      # Private network
    - "172.16.0.0/12"   # Private network
    - "192.168.0.0/16"  # Private network
  expression:
    - evt.Parsed.source_ip == '127.0.0.1'
    - evt.Parsed.source_ip contains '172.17.' # Docker default network
EOF

    # Add current public IP if requested
    echo -ne "${YELLOW}Do you want to include your current public IP in the whitelist? (y/n): ${NC}"
    read -r add_public_ip
    if [[ "$add_public_ip" =~ ^[Yy] ]]; then
    local public_ip=$(get_public_ip)
    if [[ $? -eq 0 ]]; then
        print_success "Your current public IP is: $public_ip"
        # Create a temporary file
        local temp_whitelist="${TEMP_DIR}/temp_whitelist.yaml"
        # Add the IP to the ip section
        awk -v ip="$public_ip" '
        /  ip:/ {
            print $0
            getline
            print $0
            print "    - \"" ip "\"  # Current public IP"
            next
        }
        { print }
        ' "$whitelist_file" > "$temp_whitelist"
        # Replace the original file
        mv "$temp_whitelist" "$whitelist_file"
    else
        print_error "Failed to get public IP. Continuing without it."
    fi
fi
    
    # Add custom IPs or CIDRs
    echo -ne "${YELLOW}Do you want to add additional IPs or CIDR ranges? (y/n): ${NC}"
    read -r add_custom
    if [[ "$add_custom" =~ ^[Yy] ]]; then
        echo -e "${YELLOW}Enter IP addresses or CIDR ranges (one per line, press Ctrl+D when done):${NC}"
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                if [[ "$line" == */* ]]; then
                    if validate_cidr "$line"; then
                        echo -e "    - \"$line\"  # Custom CIDR" >> "$whitelist_file"
                    else
                        print_warning "Invalid CIDR notation: $line. Skipping."
                    fi
                else
                    if validate_ip "$line"; then
                        echo -e "    - \"$line\"  # Custom IP" >> "$whitelist_file"
                    else
                        print_warning "Invalid IP: $line. Skipping."
                    fi
                fi
            fi
        done
    fi
    
    # Apply to CrowdSec
    echo -ne "${YELLOW}Apply this whitelist to CrowdSec? (y/n): ${NC}"
    read -r apply_crowdsec
    if [[ "$apply_crowdsec" =~ ^[Yy] ]]; then
        print_info "Applying whitelist to CrowdSec..."
        if ! docker cp "$whitelist_file" "crowdsec:$CROWDSEC_WHITELIST_PATH"; then
            print_error "Failed to copy whitelist to CrowdSec container."
        else
            if ! docker restart crowdsec; then
                print_error "Failed to restart CrowdSec. Please check the container logs."
            else
                print_success "Whitelist applied to CrowdSec successfully."
            fi
        fi
    fi
    
    # Apply to Traefik
    echo -ne "${YELLOW}Apply standard networks to Traefik whitelist? (y/n): ${NC}"
    read -r apply_traefik
    if [[ "$apply_traefik" =~ ^[Yy] ]]; then
        print_info "Applying standard networks to Traefik..."
        
        # Backup Traefik config
        cp "$TRAEFIK_CONFIG_PATH" "${TRAEFIK_CONFIG_PATH}.backup.$(date +%Y%m%d%H%M%S)"
        
        # Update Traefik config for each standard network
        local networks=("10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")
        for network in "${networks[@]}"; do
            add_to_traefik_whitelist "$network" || {
                print_error "Failed to add $network to Traefik. Continuing with next network."
            }
        done
        
        # Add public IP if requested
        if [[ "$add_public_ip" =~ ^[Yy] && -n "$public_ip" ]]; then
            add_to_traefik_whitelist "$public_ip" || {
                print_error "Failed to add public IP $public_ip to Traefik."
            }
        fi
        
        print_success "Standard networks applied to Traefik successfully."
    fi
    
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
                print_info "Individual IPs in CrowdSec whitelist:"
                grep -A 50 "ip:" "${TEMP_DIR}/check_whitelist.yaml" | grep -E "^ *- " | 
                sed 's/^ *- *//' | sed 's/["#].*$//' | sed '/^$/d' | sed 's/^[ \t]*//' |
                while read -r line; do
                    echo "  - $line"
                done || echo "  None found"
                
                print_info "CIDR ranges in CrowdSec whitelist:"
                grep -A 50 "cidr:" "${TEMP_DIR}/check_whitelist.yaml" | grep -E "^ *- " | 
                sed 's/^ *- *//' | sed 's/["#].*$//' | sed '/^$/d' | sed 's/^[ \t]*//' |
                while read -r line; do
                    echo "  - $line"
                done || echo "  None found"
                
                print_info "Expressions in CrowdSec whitelist:"
                grep -A 50 "expression:" "${TEMP_DIR}/check_whitelist.yaml" | grep -E "^ *- " | 
                sed 's/^ *- *//' | sed 's/["#].*$//' | sed '/^$/d' | sed 's/^[ \t]*//' |
                while read -r line; do
                    echo "  - $line"
                done || echo "  None found"
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
            done || echo "  None found"
        fi
        
        if grep -q "sourceRange:" "$TRAEFIK_CONFIG_PATH"; then
            print_info "Source Range Whitelist:"
            grep -A 20 "sourceRange:" "$TRAEFIK_CONFIG_PATH" | grep -E "^ *- " | 
            sed 's/^ *- *//' | sed 's/ *#.*$//' | sed '/^$/d' |
            while read -r line; do
                echo "  - $line"
            done || echo "  None found"
        fi
        
        if grep -q "forwardedHeadersTrustedIPs:" "$TRAEFIK_CONFIG_PATH"; then
            print_info "Forwarded Headers Trusted IPs:"
            grep -A 20 "forwardedHeadersTrustedIPs:" "$TRAEFIK_CONFIG_PATH" | grep -E "^ *- " | 
            sed 's/^ *- *//' | sed 's/ *#.*$//' | sed '/^$/d' |
            while read -r line; do
                echo "  - $line"
            done || echo "  None found"
        fi
        
        print_info "Note: Entries with /8, /16, /24, etc. are subnets that include multiple IPs"
    fi
    
    return 0
}

########################
# SCENARIOS FUNCTIONS
########################

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

########################
# CAPTCHA FUNCTIONS
########################

# Function to set up captcha protection
setup_captcha() {
    print_header "SETTING UP CAPTCHA PROTECTION"
    
    if ! check_container "crowdsec"; then
        print_error "CrowdSec container is not running. Cannot set up captcha."
        return 1
    fi
    
    if ! check_container "traefik"; then
        print_error "Traefik container is not running. Cannot set up captcha."
        return 1
    fi
    
    echo -e "${YELLOW}This will set up Cloudflare Turnstile captcha protection in CrowdSec.${NC}"
    
    if ! confirm_action "Do you want to proceed?"; then
        echo -e "${YELLOW}Captcha setup canceled.${NC}"
        return 0
    fi
    
    DYNAMIC_CONFIG_PATH="./config/traefik/dynamic_config.yml"
    
    if [[ ! -f "$DYNAMIC_CONFIG_PATH" ]]; then
        print_error "Traefik dynamic_config.yml not found at $DYNAMIC_CONFIG_PATH"
        return 1
    fi
    
    if grep -q "captchaProvider\|captchaSiteKey\|captchaSecretKey" "$DYNAMIC_CONFIG_PATH"; then
        print_warning "Captcha appears to be already configured in Traefik middleware"
        if ! confirm_action "Do you want to overwrite the existing captcha configuration?"; then
            echo -e "${YELLOW}Keeping existing captcha configuration. Returning to menu.${NC}"
            return 0
        fi
        echo -e "${YELLOW}Proceeding to update existing captcha configuration...${NC}"
    fi
    
    trap 'echo -e "\n${YELLOW}Captcha setup cancelled. Returning to menu...${NC}"; return 1' SIGINT
    
    echo -ne "${YELLOW}Enter your Cloudflare Turnstile Site Key:${NC} "
    read -r SITE_KEY || return 1
    
    if [[ -z "$SITE_KEY" ]]; then
        print_error "Site key cannot be empty."
        trap handle_sigint SIGINT
        return 1
    fi
    
    echo -ne "${YELLOW}Enter your Cloudflare Turnstile Secret Key:${NC} "
    read -r SECRET_KEY || return 1
    
    if [[ -z "$SECRET_KEY" ]]; then
        print_error "Secret key cannot be empty."
        trap handle_sigint SIGINT
        return 1
    fi
    
    trap handle_sigint SIGINT
    
    echo -e "${YELLOW}Creating captcha remediation profile...${NC}"
    
    PROFILES_PATH="./config/crowdsec/profiles.yaml"
    if [[ ! -f "$PROFILES_PATH" ]]; then
        cat > "$PROFILES_PATH" << EOF
name: captcha_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "http"
decisions:
 - type: captcha
   duration: 4h
on_success: break

---
name: default_ip_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 4h
on_success: break
EOF
        print_success "Created new profiles.yaml with captcha configuration"
    else
        if grep -q "captcha_remediation" "$PROFILES_PATH"; then
            print_warning "Captcha profile already exists in profiles.yaml"
        else
            TMP_PROFILE="${TEMP_DIR}/captcha_profile.yaml"
            TMP_NEW_PROFILES="${TEMP_DIR}/new_profiles.yaml"
            
            cat > "$TMP_PROFILE" << EOF
name: captcha_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "http"
decisions:
 - type: captcha
   duration: 4h
on_success: break

---
EOF
            cat "$TMP_PROFILE" "$PROFILES_PATH" > "$TMP_NEW_PROFILES"
            
            if ! mv "$TMP_NEW_PROFILES" "$PROFILES_PATH"; then
                print_error "Failed to update profiles.yaml"
                return 1
            fi
            
            print_success "Added captcha profile to existing profiles.yaml"
        fi
    fi
    
    TRAEFIK_CONF_DIR="./config/traefik/conf"
    mkdir -p "$TRAEFIK_CONF_DIR"
    
    CAPTCHA_HTML_PATH="$TRAEFIK_CONF_DIR/captcha.html"
    echo -e "${YELLOW}Creating captcha HTML template...${NC}"
    
    cat > "$CAPTCHA_HTML_PATH" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <title>CrowdSec Captcha</title>
  <meta content="text/html; charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    *,:after,:before{border:0 solid #e5e7eb;box-sizing:border-box}:after,:before{--tw-content:""}html{-webkit-text-size-adjust:100%;font-feature-settings:normal;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;line-height:1.5;-moz-tab-size:4;-o-tab-size:4;tab-size:4}body{line-height:inherit;margin:0}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}*,::backdrop,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x:;--tw-pan-y:;--tw-pinch-zoom:;--tw-scroll-snap-strictness:proximity;--tw-ordinal:;--tw-slashed-zero:;--tw-numeric-figure:;--tw-numeric-spacing:;--tw-numeric-fraction:;--tw-ring-inset:;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:#3b82f680;--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur:;--tw-brightness:;--tw-contrast:;--tw-grayscale:;--tw-hue-rotate:;--tw-invert:;--tw-saturate:;--tw-sepia:;--tw-drop-shadow:;--tw-backdrop-blur:;--tw-backdrop-brightness:;--tw-backdrop-contrast:;--tw-backdrop-grayscale:;--tw-backdrop-hue-rotate:;--tw-backdrop-invert:;--tw-backdrop-opacity:;--tw-backdrop-saturate:;--tw-backdrop-sepia:}.flex{display:flex}.flex-wrap{flex-wrap:wrap}.inline-flex{display:inline-flex}.h-24{height:6rem}.h-6{height:1.5rem}.h-full{height:100%}.h-screen{height:100vh}.text-center{text-align:center}.w-24{width:6rem}.w-6{width:1.5rem}.w-full{width:100%}.w-screen{width:100vw}.my-3{margin-top:0.75rem;margin-bottom:0.75rem}.flex-col{flex-direction:column}.items-center{align-items:center}.justify-center{justify-content:center}.justify-between{justify-content:space-between}.space-y-1>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(.25rem*var(--tw-space-y-reverse));margin-top:calc(.25rem*(1 - var(--tw-space-y-reverse)))}.space-y-4>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(1rem*var(--tw-space-y-reverse));margin-top:calc(1rem*(1 - var(--tw-space-y-reverse)))}.rounded-xl{border-radius:.75rem}.border-2{border-width:2px}.border-black{--tw-border-opacity:1;border-color:rgb(0 0 0/var(--tw-border-opacity))}.p-4{padding:1rem}.px-4{padding-left:1rem;padding-right:1rem}.py-2{padding-bottom:.5rem;padding-top:.5rem}.text-2xl{font-size:1.5rem;line-height:2rem}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xl{font-size:1.25rem;line-height:1.75rem}.font-bold{font-weight:700}.text-white{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity))}@media (min-width:640px){.sm\:w-2\/3{width:66.666667%}}@media (min-width:768px){.md\:flex-row{flex-direction:row}}@media (min-width:1024px){.lg\:w-1\/2{width:50%}.lg\:text-3xl{font-size:1.875rem;line-height:2.25rem}.lg\:text-xl{font-size:1.25rem;line-height:1.75rem}}@media (min-width:1280px){.xl\:text-4xl{font-size:2.25rem;line-height:2.5rem}}
  </style>
  <script src="{{ .FrontendJS }}" async defer></script>
</head>
<body class="h-screen w-screen p-4">
  <div class="h-full w-full flex flex-col justify-center items-center">
    <div class="border-2 border-black rounded-xl p-4 text-center w-full sm:w-2/3 lg:w-1/2">
      <div class="flex flex-col items-center space-y-4">
        <svg fill="black" class="h-24 w-24" aria-hidden="true" focusable="false" data-prefix="fas" data-icon="exclamation-triangle" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512" class="warning"><path d="M569.517 440.013C587.975 472.007 564.806 512 527.94 512H48.054c-36.937 0-59.999-40.055-41.577-71.987L246.423 23.985c18.467-32.009 64.72-31.951 83.154 0l239.94 416.028zM288 354c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h48.546c6.373 0 11.635-4.982 11.982-11.346l7.418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z"></path></svg>
        <h1 class="text-2xl lg:text-3xl xl:text-4xl">CrowdSec Captcha</h1>
      </div>
      <form action="" method="POST" class="flex flex-col space-y-1" id="captcha-form">
        <div id="captcha" class="{{ .FrontendKey }}" data-sitekey="{{ .SiteKey }}" data-callback="captchaCallback"></div>
      </form>
      <div class="flex justify-center flex-wrap">
        <p class="my-3">This security check has been powered by</p>
        <a href="https://crowdsec.net/" target="_blank" rel="noopener" class="inline-flex flex-col items-center">
          <svg fill="black" width="33.92" height="33.76" viewBox="0 0 254.4 253.2"><defs><clipPath id="a"><path d="M0 52h84v201.2H0zm0 0"/></clipPath><clipPath id="b"><path d="M170 52h84.4v201.2H170zm0 0"/></clipPath></defs><path d="M59.3 128.4c1.4 2.3 2.5 4.6 3.4 7-1-4.1-2.3-8.1-4.3-12-3.1-6-7.8-5.8-10.7 0-2 4-3.2 8-4.3 12.1 1-2.4 2-4.8 3.4-7.1 3.4-5.8 8.8-6 12.5 0M207.8 128.4a42.9 42.9 0 013.4 7c-1-4.1-2.3-8.1-4.3-12-3.2-6-7.8-5.8-10.7 0-2 4-3.3 8-4.3 12.1.9-2.4 2-4.8 3.4-7.1 3.4-5.8 8.8-6 12.5 0M134.6 92.9c2 3.5 3.6 7 4.8 10.7-1.3-5.4-3-10.6-5.6-15.7-4-7.5-9.7-7.2-13.3 0a75.4 75.4 0 00-5.6 16c1.2-3.8 2.7-7.4 4.7-11 4.1-7.2 10.6-7.5 15 0M43.8 136.8c.9 4.6 3.7 8.3 7.3 9.2 0 2.7 0 5.5.2 8.2.3 3.3.4 6.6 1 9.6.3 2.3 1 2.2 1.3 0 .5-3 .6-6.3 1-9.6l.2-8.2c3.5-1 6.4-4.6 7.2-9.2a17.8 17.8 0 01-9 2.4c-3.5 0-6.6-1-9.2-2.4M192.4 136.8c.8 4.6 3.7 8.3 7.2 9.2 0 2.7 0 5.5.3 8.2.3 3.3.4 6.6 1 9.6.3 2.3.9 2.2 1.2 0 .6-3 .7-6.3 1-9.6.2-2.7.3-5.5.2-8.2 3.6-1 6.4-4.6 7.3-9.2a17.8 17.8 0 01-9.1 2.4c-3.4 0-6.6-1-9.1-2.4M138.3 104.6c-3.1 1.9-7 3-11.3 3-4.3 0-8.2-1.1-11.3-3 1 5.8 4.5 10.3 9 11.5 0 3.4 0 6.8.3 10.2.4 4.1.5 8.2 1.2 12 .4 2.9 1.2 2.7 1.6 0 .7-3.8.8-7.9 1.2-12 .3-3.4.3-6.8.3-10.2 4.5-1.2 8-5.7 9-11.5"/><path d="M51 146c0 2.7.1 5.5.3 8.2.3 3.3.4 6.6 1 9.6.3 2.3 1 2.2 1.3 0 .5-3 .6-6.3 1-9.6l.2-8.2c3.5-1 6.4-4.6 7.2-9.2a17.8 17.8 0 01-9 2.4c-3.5 0-6.6-1-9.2-2.4.9 4.6 3.7 8.3 7.3 9.2M143.9 105c-1.9-.4-3.5-1.2-4.9-2.3 1.4 5.6 2.5 11.3 4 17 1.2 5 2 10 2.4 15 .6 7.8-4.5 14.5-10.9 14.5h-15c-6.4 0-11.5-6.7-11-14.5.5-5 1.3-10 2.6-15 1.3-5.3 2.3-10.5 3.6-15.7-2.2 1.2-4.8 1.9-7.7 2-4.7.1-9.4-.3-14-1-4-.4-6.7-3-8-6.7-1.3-3.4-2-7-3.3-10.4-.5-1.5-1.6-2.8-2.4-4.2-.4-.6-.8-1.2-.9-1.8v-7.8a77 77 0 0124.5-3c6.1 0 12 1 17.8 3.2 4.7 1.7 9.7 1.8 14.4 0 9-3.4 18.2-3.8 27.5-3 4.9.5 9.8 1.6 14.8 2.4v8.2c0 .6-.3 1.5-.7 1.7-2 .9-2.2 2.7-2.7 4.5-.9 3.2-1.8 6.4-2.9 9.5a11 11 0 01-8.8 7.7 40.6 40.6 0 01-18.4-.2m29.4 80.6c-3.2-26.8-6.4-50-8.9-60.7a14.3 14.3 0 0014.1-14h.4a9 9 0 005.6-16.5 14.3 14.3 0 00-3.7-27.2 9 9 0 00-6.9-14.6c2.4-1.1 4.5-3 5.8-5 3.4-5.3 4-29-8-44.4-5-6.3-9.8-2.5-10 1.8-1 13.2-1.1 23-4.5 34.3a9 9 0 00-16-4.1 14.3 14.3 0 00-28.4 0 9 9 0 00-16 4.1c-3.4-11.2-3.5-21.1-4.4-34.3-.3-4.3-5.2-8-10-1.8-12 15.3-11.5 39-8.1 44.4 1.3 2 3.4 3.9 5.8 5a9 9 0 00-7 14.6 14.3 14.3 0 00-3.6 27.2A9 9 0 0075 111h.5a14.5 14.5 0 0014.3 14c-4 17.2-10 66.3-15 111.3l-1.3 13.4a1656.4 1656.4 0 01106.6 0l-1.4-12.7-5.4-51.3"/><g clip-path="url(#a)"><path d="M83.5 136.6l-2.3.7c-5 1-9.8 1-14.8-.2-1.4-.3-2.7-1-3.8-1.9l3.1 13.7c1 4 1.7 8 2 12 .5 6.3-3.6 11.6-8.7 11.6H46.9c-5.1 0-9.2-5.3-8.7-11.6.3-4 1-8 2-12 1-4.2 1.8-8.5 2.9-12.6-1.8 1-3.9 1.5-6.3 1.6a71 71 0 01-11.1-.7 7.7 7.7 0 01-6.5-5.5c-1-2.7-1.6-5.6-2.6-8.3-.4-1.2-1.3-2.3-2-3.4-.2-.4-.6-1-.6-1.4v-6.3c6.4-2 13-2.6 19.6-2.5 4.9.1 9.6 1 14.2 2.6 3.9 1.4 7.9 1.5 11.7 0 1.8-.7 3.6-1.2 5.5-1.6a13 13 0 01-1.6-15.5A18.3 18.3 0 0159 73.1a11.5 11.5 0 00-17.4 8.1 7.2 7.2 0 00-12.9 3.3c-2.7-9-2.8-17-3.6-27.5-.2-3.4-4-6.5-8-1.4C7.5 67.8 7.9 86.9 10.6 91c1.1 1.7 2.8 3.1 4.7 4a7.2 7.2 0 00-5.6 11.7 11.5 11.5 0 00-2.9 21.9 7.2 7.2 0 004.5 13.2h.3c0 .6 0 1.1.2 1.7.9 5.4 5.6 9.5 11.3 9.5A1177.2 1177.2 0 0010 253.2c18.1-1.5 38.1-2.6 59.5-3.4.4-4.6.8-9.3 1.4-14 1.2-11.6 3.3-30.5 5.7-49.7 2.2-18 4.7-36.3 7-49.5"/></g><g clip-path="url(#b)"><path d="M254.4 118.2c0-5.8-4.2-10.5-9.7-11.4a7.2 7.2 0 00-5.6-11.7c2-.9 3.6-2.3 4.7-4 2.7-4.2 3.1-23.3-6.5-35.5-4-5.1-7.8-2-8 1.4-.8 10.5-.9 18.5-3.6 27.5a7.2 7.2 0 00-12.8-3.3 11.5 11.5 0 00-17.8-7.9 18.4 18.4 0 01-4.5 22 13 13 0 01-1.3 15.2c2.4.5 4.8 1 7.1 2 3.8 1.3 7.8 1.4 11.6 0 7.2-2.8 14.6-3 22-2.4 4 .4 7.9 1.2 12 1.9l-.1 6.6c0 .5-.2 1.2-.5 1.3-1.7.7-1.8 2.2-2.2 3.7l-2.3 7.6a8.8 8.8 0 01-7 6.1c-5 1-10 1-14.9-.2-1.5-.3-2.8-1-3.9-1.9 1.2 4.5 2 9.1 3.2 13.7 1 4 1.6 8 2 12 .4 6.3-3.6 11.6-8.8 11.6h-12c-5.2 0-9.3-5.3-8.8-11.6.4-4 1-8 2-12 1-4.2 1.9-8.5 3-12.6-1.8 1-4 1.5-6.3 1.6-3.7 0-7.5-.3-11.2-.7a7.7 7.7 0 01-3.7-1.5c3.1 18.4 7.1 51.2 12.5 100.9l.6 5.3.8 7.9c21.4.7 41.5 1.9 59.7 3.4L243 243l-4.4-41.2a606 606 0 00-7-48.7 11.5 11.5 0 0011.2-11.2h.4a7.2 7.2 0 004.4-13.2c4-1.8 6.8-5.8 6.8-10.5"/></g><path d="M180 249.6h.4a6946 6946 0 00-7.1-63.9l5.4 51.3 1.4 12.6M164.4 125c2.5 10.7 5.7 33.9 8.9 60.7a570.9 570.9 0 00-8.9-60.7M74.8 236.3l-1.4 13.4 1.4-13.4"/>
          </svg>
          <span>CrowdSec</span>
        </a>
      </div>
    </div>
  </div>
  <script>
    function captchaCallback() {
      setTimeout(() => document.querySelector('#captcha-form').submit(), 500);
    }
  </script>
</body>
</html>
EOF
    
    print_success "Created captcha.html template"
    
    echo -e "${YELLOW}Updating Traefik middleware configuration...${NC}"
    
    BACKUP_CONFIG="${DYNAMIC_CONFIG_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    if ! cp "$DYNAMIC_CONFIG_PATH" "$BACKUP_CONFIG"; then
        print_error "Failed to create backup of dynamic_config.yml"
        return 1
    fi
    
    print_success "Created backup of dynamic_config.yml at $BACKUP_CONFIG"
    
    if grep -q "crowdsec:" "$DYNAMIC_CONFIG_PATH"; then
        TEMP_CONFIG="${TEMP_DIR}/dynamic_config.yml.tmp"
        
        sed '/captchaProvider\|captchaSiteKey\|captchaSecretKey\|captchaGracePeriodSeconds\|captchaHTMLFilePath/d' "$DYNAMIC_CONFIG_PATH" > "$TEMP_CONFIG"
        
        sed -i "/crowdsec:/,/enabled: true/ s/enabled: true/enabled: true\n          captchaProvider: turnstile\n          captchaSiteKey: \"$SITE_KEY\"\n          captchaSecretKey: \"$SECRET_KEY\"\n          captchaGracePeriodSeconds: 1800\n          captchaHTMLFilePath: \"\/etc\/traefik\/conf\/captcha.html\"/" "$TEMP_CONFIG"
        
        if ! mv "$TEMP_CONFIG" "$DYNAMIC_CONFIG_PATH"; then
            print_error "Failed to update crowdsec middleware configuration"
            cp "$BACKUP_CONFIG" "$DYNAMIC_CONFIG_PATH"
            return 1
        fi
        
        print_success "Updated existing crowdsec middleware with captcha configuration"
    else
        print_error "crowdsec middleware not found in dynamic_config.yml"
        print_warning "Make sure you have the crowdsec middleware configured first"
        return 1
    fi
    
    echo -e "${YELLOW}Restarting Traefik to apply changes...${NC}"
    if ! docker restart traefik; then
        print_error "Failed to restart Traefik container"
        return 1
    fi
    
    sleep 5
    
    echo -e "${YELLOW}Restarting CrowdSec to apply profile changes...${NC}"
    if ! docker restart crowdsec; then
        print_error "Failed to restart CrowdSec container"
        return 1
    fi
    
    sleep 5
    
    echo -e "\n${GREEN}Captcha protection setup completed.${NC}"
    echo -e "${YELLOW}Note: To test the captcha, you can add a test captcha decision:${NC}"
    echo -e "${CYAN}docker exec crowdsec cscli decisions add --ip <test-ip> --type captcha -d 1h${NC}"
    
    return 0
}

########################
# HEALTH CHECK FUNCTIONS
########################

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

# Function to analyze Traefik logs with advanced options
analyze_traefik_logs_advanced() {
    print_header "ADVANCED TRAEFIK LOG ANALYSIS"
    
    # Check for log file
    local log_file="./config/traefik/logs/access.log"
    if [[ ! -f "$log_file" ]]; then
        print_warning "Default log file not found at $log_file"
        echo -ne "${YELLOW}Enter alternative log file path (or press Enter to cancel): ${NC}"
        read -r alternative_log
        if [[ -z "$alternative_log" ]]; then
            print_error "No log file specified. Returning to menu."
            return 1
        fi
        log_file="$alternative_log"
        if [[ ! -f "$log_file" ]]; then
            print_error "Specified log file not found: $log_file"
            return 1
        fi
    fi
    
    print_info "Using log file: $log_file"
    print_info "Analyzing..."
    
    # Create temp directory for analysis
    local analysis_dir="${TEMP_DIR}/traefik_analysis"
    mkdir -p "$analysis_dir"
    
    # Detect format
    if head -n 1 "$log_file" | grep -q "{"; then
        print_info "Detected JSON log format"
        FORMAT="json"
    else
        print_info "Detected Common log format"
        FORMAT="common"
    fi
    
    # Basic log statistics
    local log_lines=$(wc -l < "$log_file")
    print_info "Total log lines: $log_lines"
    
    # Analyze top IPs
    print_header "Top Client IPs"
    if [[ "$FORMAT" == "json" ]]; then
        jq -r '.ClientHost' "$log_file" 2>/dev/null | sort | uniq -c | sort -nr | head -10 || 
            print_error "Failed to extract IPs from JSON log"
    else
        awk '{print $1}' "$log_file" | sort | uniq -c | sort -nr | head -10 || 
            print_error "Failed to extract IPs from log"
    fi
    
    # Analyze status codes
    print_header "HTTP Status Code Distribution"
    if [[ "$FORMAT" == "json" ]]; then
        jq -r '.DownstreamStatus' "$log_file" 2>/dev/null | sort | uniq -c | sort -nr || 
            print_error "Failed to extract status codes from JSON log"
    else
        awk '{print $9}' "$log_file" | sort | uniq -c | sort -nr || 
            print_error "Failed to extract status codes from log"
    fi
    
    # Analyze HTTP methods
    print_header "HTTP Methods Usage"
    if [[ "$FORMAT" == "json" ]]; then
        jq -r '.RequestMethod' "$log_file" 2>/dev/null | sort | uniq -c | sort -nr || 
            print_error "Failed to extract HTTP methods from JSON log"
    else
        awk '{print $6}' "$log_file" | tr -d '"' | sort | uniq -c | sort -nr || 
            print_error "Failed to extract HTTP methods from log"
    fi
    
    # Analyze errors
    print_header "Error Analysis (Status >= 400)"
if [[ "$FORMAT" == "json" ]]; then
    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        print_error "jq is not installed. Cannot fully analyze JSON logs."
    else
        # Try to extract errors with proper error handling
        jq -r 'select(.DownstreamStatus >= 400) | [.DownstreamStatus, .ClientHost, .RequestPath] | @tsv' "$log_file" 2>/dev/null | 
            sort | uniq -c | sort -nr | head -10 || 
            print_error "Failed to extract errors from JSON log"
    fi
else
    awk '$9 >= 400 {print $9, $1, $7}' "$log_file" | sort | uniq -c | sort -nr | head -10 || 
        print_error "Failed to extract errors from log"
fi

    
    # Cleanup
    rm -rf "$analysis_dir" 2>/dev/null || true
    
    press_enter_to_continue
    return 0
}

########################
# IP MANAGEMENT FUNCTIONS
########################

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

    print_info "Checking security status for IP: $ip"
    
    # Check if IP is blocked in CrowdSec
    if is_ip_blocked "$ip"; then
        print_warning "IP $ip is currently BLOCKED by CrowdSec."
        print_info "Decision details:"
        ( docker exec crowdsec cscli decisions list -o human | grep "$ip" ) || 
        print_info "No detailed information available."
    else
        print_success "IP $ip is NOT currently blocked by CrowdSec."
    fi

# Check if IP is whitelisted in CrowdSec
local crowdsec_whitelist="/etc/crowdsec/parsers/s02-enrich/whitelists.yaml"
local ip_whitelisted_in_crowdsec=false

if docker exec crowdsec test -f "$crowdsec_whitelist" 2>/dev/null; then
    docker cp "crowdsec:$crowdsec_whitelist" "${TEMP_DIR}/check_whitelist.yaml" 2>/dev/null
    if [[ -f "${TEMP_DIR}/check_whitelist.yaml" ]]; then
        # Check direct IP match
        if grep -F "\"$ip\"" "${TEMP_DIR}/check_whitelist.yaml" > /dev/null 2>&1 || 
           grep -F "- \"$ip\"" "${TEMP_DIR}/check_whitelist.yaml" > /dev/null 2>&1 || 
           grep -F "- $ip" "${TEMP_DIR}/check_whitelist.yaml" > /dev/null 2>&1; then
            print_success "IP $ip is explicitly whitelisted in CrowdSec."
            ip_whitelisted_in_crowdsec=true
        else
            # Extract CIDR ranges with improved pattern matching
            # First check if there's a cidr section
            if grep -q "^[[:space:]]*cidr:" "${TEMP_DIR}/check_whitelist.yaml"; then
                # Get all CIDR ranges, handling quotes properly
                local cidr_section=$(sed -n '/^[[:space:]]*cidr:/,/^[[:space:]]*[a-z]/ p' "${TEMP_DIR}/check_whitelist.yaml")
                local cidr_ranges=$(echo "$cidr_section" | grep "^[[:space:]]*-" | sed 's/^[[:space:]]*-[[:space:]]*//g' | sed 's/"//g' | sed 's/#.*$//' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                
                # Check each CIDR range
                while IFS= read -r cidr; do
                    if [[ -n "$cidr" ]] && is_ip_in_subnet "$ip" "$cidr"; then
                        print_success "IP $ip is covered by CIDR range $cidr in CrowdSec whitelist."
                        ip_whitelisted_in_crowdsec=true
                        break
                    fi
                done <<< "$cidr_ranges"
            fi
            
            if [[ "$ip_whitelisted_in_crowdsec" == "false" ]]; then
                print_warning "IP $ip is NOT whitelisted in CrowdSec."
            fi
        fi
    else
        print_error "Failed to copy whitelist from CrowdSec container."
    fi
else
    print_warning "No CrowdSec whitelist file found."
fi


 # Check if IP is whitelisted in Traefik
if [[ -f "$TRAEFIK_CONFIG_PATH" ]]; then
    local ip_whitelisted_in_traefik=false
    
    # Check direct IP match
    if grep -F "- $ip" "$TRAEFIK_CONFIG_PATH" > /dev/null 2>&1; then
        print_success "IP $ip is explicitly whitelisted in Traefik configuration."
        ip_whitelisted_in_traefik=true
    else
        # Check for CIDR ranges in Traefik config
        local traefik_cidrs=$(grep -A 50 "clientTrustedIPs\|sourceRange\|forwardedHeadersTrustedIPs\|ipWhitelist" "$TRAEFIK_CONFIG_PATH" | 
                             grep -E "^ *- " | grep "/" | sed 's/^ *- *//' | sed 's/#.*$//' | 
                             grep -v "^$" || echo "")
        
        if [[ -n "$traefik_cidrs" ]]; then
            while IFS= read -r cidr; do
                if is_ip_in_subnet "$ip" "$cidr"; then
                    print_success "IP $ip is covered by CIDR range $cidr in Traefik configuration."
                    ip_whitelisted_in_traefik=true
                    break
                fi
            done <<< "$traefik_cidrs"
        fi
        
        if [[ "$ip_whitelisted_in_traefik" == "false" ]]; then
            print_warning "IP $ip is NOT whitelisted in Traefik configuration."
        fi
    fi
else
    print_warning "Traefik configuration file not found."
fi
    
    return 0
}

########################
# BACKUP FUNCTIONS
########################

# Validate backup directory
validate_backup_dir() {
    if [[ ! -d "${BACKUP_DIR}" ]]; then
        if [[ "${DRY_RUN}" == true ]]; then
            log "INFO" "DRY-RUN: Would create backup directory: ${BACKUP_DIR}"
        else
            mkdir -p "${BACKUP_DIR}" || { log "ERROR" "Failed to create backup directory: ${BACKUP_DIR}"; return 1; }
            log "INFO" "Created backup directory: ${BACKUP_DIR}"
        fi
    fi
    [[ ! -w "${BACKUP_DIR}" && "${DRY_RUN}" == false ]] && { log "ERROR" "Backup directory is not writable: ${BACKUP_DIR}"; return 1; }
    return 0
}
# Check if Docker is available and running
check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        log "ERROR" "Docker is not installed or not in PATH"
        return 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        log "ERROR" "Docker daemon is not running or not accessible"
        return 1
    fi
    
    log "INFO" "Docker is available and running"
    return 0
}
# Check if stack services are running properly
check_stack() {
    log "INFO" "Checking if Pangolin stack services are running..."
    
    local all_services_up=true
    
    # Check if docker-compose.yml exists
    if [[ ! -f "${DOCKER_COMPOSE_FILE}" ]]; then
        log "WARNING" "Docker compose file not found: ${DOCKER_COMPOSE_FILE}"
        return 1
    fi
    
    # Check if services are running
    for service in "${SERVICES[@]}"; do
        if ! docker ps --format '{{.Names}}' | grep -q "${service}"; then
            log "WARNING" "Service ${service} is not running"
            all_services_up=false
        else
            log "INFO" "Service ${service} is running"
        fi
    done
    
    if [[ "${all_services_up}" == false ]]; then
        log "WARNING" "Not all stack services are running"
        return 1
    fi
    
    log "INFO" "All stack services are running properly"
    return 0
}
# Create backup
create_backup() {
    print_header "CREATING BACKUP"
    
    local backup_name="pangolin_backup_${BACKUP_TIMESTAMP}"
    local backup_path="${BACKUP_DIR}/${backup_name}"
    local archive_path="${backup_path}.tar.gz"
    
    log "INFO" "Starting backup process..."
    
    validate_backup_dir || return 1
    check_docker || return 1
    check_stack || log "WARNING" "Stack check failed, but continuing with backup."
    
    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "DRY-RUN: Would create backup in ${backup_path}"
        for item in "${BACKUP_ITEMS[@]}"; do
            local source_path="${PANGOLIN_DIR}/${item}"
            [[ -e "${source_path}" ]] && log "INFO" "DRY-RUN:   - ${item}" || log "WARNING" "DRY-RUN:   - ${item} (does not exist)"
        done
        log "SUCCESS" "DRY-RUN: Backup simulation completed successfully"
        return 0
    fi
    
    local temp_backup_path=$(mktemp -d) || { log "ERROR" "Failed to create temporary backup directory"; return 1; }
    temp_dir="${temp_backup_path}"
    
    for item in "${BACKUP_ITEMS[@]}"; do
        local source_path="${PANGOLIN_DIR}/${item}"
        if [[ ! -e "${source_path}" ]]; then
            log "WARNING" "Source path does not exist: ${source_path}"
            continue
        fi
        mkdir -p "${temp_backup_path}/$(dirname "${item}")" || return 1
        cp -a "${source_path}" "${temp_backup_path}/${item}" || return 1
        log "INFO" "Copied: ${item}"
    done
    
    {
        printf "Backup created: %s\n" "$(date)"
        printf "Pangolin directory: %s\n" "${PANGOLIN_DIR}"
        printf "Items included:\n"
        for item in "${BACKUP_ITEMS[@]}"; do
            printf "  %s\n" "${item}"
        done
    } > "${temp_backup_path}/BACKUP_INFO.txt" || return 1
    
    tar -czf "${archive_path}" -C "$(dirname "${temp_backup_path}")" "$(basename "${temp_backup_path}")" || { log "ERROR" "Failed to create archive: ${archive_path}"; return 1; }
    
    rm -rf "${temp_backup_path}" 2>/dev/null || true
    local archive_size=$(du -h "${archive_path}" 2>/dev/null | cut -f1) || archive_size="unknown size"
    log "SUCCESS" "Backup created successfully: ${archive_path} (${archive_size})"
    
    cleanup_old_backups
    return 0
}

# Cleanup old backups
cleanup_old_backups() {
    log "INFO" "Checking for old backups to remove..."
    
    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "DRY-RUN: Would remove backups older than ${RETENTION_DAYS} days"
        return 0
    fi
    
    local cutoff_date
    if [[ "$(uname)" == "Darwin" ]]; then
        cutoff_date=$(date -v-"${RETENTION_DAYS}"d +%Y%m%d)
    else
        cutoff_date=$(date -d "${RETENTION_DAYS} days ago" +%Y%m%d)
    fi
    
    local count=0
    shopt -s nullglob
    local backup_files=("${BACKUP_DIR}"/pangolin_backup_*.tar.gz)
    shopt -u nullglob
    
    for backup in "${backup_files[@]}"; do
        [[ ! -f "${backup}" ]] && continue
        local backup_date=$(basename "${backup}" | grep -oE 'pangolin_backup_[0-9]{8}' | cut -d'_' -f3 || echo "")
        if [[ -n "${backup_date}" && "${backup_date}" -lt "${cutoff_date}" ]]; then
            log "INFO" "Removing old backup: $(basename "${backup}")"
            rm -f "${backup}" && ((count++)) || log "WARNING" "Failed to remove backup: ${backup}"
        fi
    done
    
    [[ ${count} -eq 0 ]] && log "INFO" "No old backups to remove." || log "SUCCESS" "Removed ${count} old backup(s)."
}

# List available backups
list_backups() {
    print_header "Available Backups"
    
    shopt -s nullglob
    local backup_files=("${BACKUP_DIR}"/pangolin_backup_*.tar.gz)
    shopt -u nullglob
    
    if [[ ${#backup_files[@]} -eq 0 ]]; then
        printf "No backups found in %s\n" "${BACKUP_DIR}"
        BACKUPS_ARRAY=()
        return 0
    fi
    
    readarray -t backups < <(printf '%s\n' "${backup_files[@]}" | sort -r)
    BACKUPS_ARRAY=("${backups[@]}")
    
    printf "${CYAN}Found %d backup(s):${NC}\n\n" "${#backups[@]}"
    for i in "${!backups[@]}"; do
        local backup="${backups[$i]}"
        local filename=$(basename "${backup}")
        local size=$(du -h "${backup}" 2>/dev/null | cut -f1 || echo "unknown size")
        local date_part=$(echo "${filename}" | grep -oE 'pangolin_backup_[0-9]{8}_[0-9]{6}' | cut -d'_' -f2,3 || echo "")
        local formatted_date="Unknown date"
        if [[ -n "${date_part}" ]]; then
            local year="${date_part:0:4}"
            local month="${date_part:4:2}"
            local day="${date_part:6:2}"
            local hour="${date_part:9:2}"
            local minute="${date_part:11:2}"
            local second="${date_part:13:2}"
            formatted_date="${year}-${month}-${day} ${hour}:${minute}:${second}"
        fi
        printf "${YELLOW}[%d]${NC} %s (%s) - %s\n" "${i}" "${filename}" "${size}" "${formatted_date}"
    done
    printf "\n"
    return 0
}

# Delete specific backups
delete_backups() {
    print_header "Delete Backups"
    
    list_backups
    if [[ ${#BACKUPS_ARRAY[@]} -eq 0 ]]; then
        log "ERROR" "No backups available for deletion."
        press_enter_to_continue
        return 0
    fi
    
    printf "${YELLOW}Enter the index of the backup to delete, multiple indexes separated by spaces, 'a' for all, or 'c' to cancel:${NC}\n"
    local selection
    read -r selection
    
    if [[ "${selection,,}" == "c" ]]; then
        log "INFO" "Deletion cancelled by user."
        return 0
    fi
    
    if [[ "${selection,,}" == "a" ]]; then
        printf "${YELLOW}Are you ABSOLUTELY SURE you want to delete ALL backups? (Type 'YES' to confirm):${NC}\n"
        local confirmation
        read -r confirmation
        [[ "${confirmation^^}" != "YES" ]] && { log "INFO" "Deletion cancelled by user."; return 0; }
        
        if [[ "${DRY_RUN}" == true ]]; then
            log "INFO" "DRY-RUN: Would delete all ${#BACKUPS_ARRAY[@]} backups"
            return 0
        fi
        
        local deleted_count=0
        for backup in "${BACKUPS_ARRAY[@]}"; do
            log "INFO" "Deleting backup: $(basename "${backup}")"
            rm -f "${backup}" && ((deleted_count++)) || log "WARNING" "Failed to delete backup: ${backup}"
        done
        log "SUCCESS" "Deleted ${deleted_count} of ${#BACKUPS_ARRAY[@]} backups"
        return 0
    fi
    
    local indexes=()
    read -ra indexes <<< "${selection}"
    for index in "${indexes[@]}"; do
        if ! [[ "${index}" =~ ^[0-9]+$ ]] || [[ "${index}" -ge "${#BACKUPS_ARRAY[@]}" ]]; then
            log "ERROR" "Invalid selection: ${index}"
            press_enter_to_continue
            return 0
        fi
    done
    
    if [[ ${#indexes[@]} -eq 1 ]]; then
        local backup_to_delete="${BACKUPS_ARRAY[${indexes[0]}]}"
        printf "${YELLOW}Are you sure you want to delete: %s? (y/n):${NC}\n" "$(basename "${backup_to_delete}")"
    else
        printf "${YELLOW}Are you sure you want to delete %d selected backups? (y/n):${NC}\n" "${#indexes[@]}"
    fi
    local confirm
    read -r confirm
    [[ "${confirm,,}" != "y" ]] && { log "INFO" "Deletion cancelled by user."; return 0; }
    
    if [[ "${DRY_RUN}" == true ]]; then
        for index in "${indexes[@]}"; do
            log "INFO" "DRY-RUN: Would delete backup: $(basename "${BACKUPS_ARRAY[${index}]}")"
        done
        return 0
    fi
    
    local deleted_count=0
    for index in "${indexes[@]}"; do
        local backup_to_delete="${BACKUPS_ARRAY[${index}]}"
        log "INFO" "Deleting backup: $(basename "${backup_to_delete}")"
        rm -f "${backup_to_delete}" && { ((deleted_count++)); log "SUCCESS" "Deleted backup: $(basename "${backup_to_delete}")"; } || log "ERROR" "Failed to delete backup: $(basename "${backup_to_delete}")"
    done
    log "INFO" "Deleted ${deleted_count} of ${#indexes[@]} selected backups"
    return 0
}

# Find latest backup
find_latest_backup() {
    shopt -s nullglob
    local backup_files=("${BACKUP_DIR}"/pangolin_backup_*.tar.gz)
    shopt -u nullglob
    [[ ${#backup_files[@]} -eq 0 ]] && { log "ERROR" "No valid backup found in ${BACKUP_DIR}"; return 1; }
    local latest_backup=$(printf '%s\n' "${backup_files[@]}" | sort -r | head -n1)
    printf "%s" "${latest_backup}"
}

# Validate backup contents
validate_backup() {
    local backup_dir="$1"
    [[ ! -d "${backup_dir}" || ! -r "${backup_dir}" ]] && { log "ERROR" "Invalid or unreadable backup directory: ${backup_dir}"; return 1; }
    [[ ! -f "${backup_dir}/docker-compose.yml" || ! -r "${backup_dir}/docker-compose.yml" ]] && { log "ERROR" "Missing or unreadable docker-compose.yml"; return 1; }
    [[ ! -d "${backup_dir}/config" || ! -r "${backup_dir}/config" ]] && { log "ERROR" "Missing or unreadable config backup"; return 1; }
    return 0
}

# Restore from backup
restore_backup() {
    print_header "Restore from Backup"
    
    local selected_backup=""
    if [[ -n "${1:-}" ]]; then
        selected_backup="$1"
        [[ ! -f "${selected_backup}" ]] && { log "ERROR" "Specified backup file does not exist: ${selected_backup}"; press_enter_to_continue; return 0; }
        log "INFO" "Using specified backup: ${selected_backup}"
    else
        list_backups
        [[ ${#BACKUPS_ARRAY[@]} -eq 0 ]] && { log "ERROR" "No backups available for restore."; press_enter_to_continue; return 0; }
        
        printf "${YELLOW}Enter the index of the backup to restore, 'l' for latest, or 'c' to cancel:${NC}\n"
        local selection
        read -r selection
        
        if [[ "${selection,,}" == "c" ]]; then
            log "INFO" "Restore cancelled by user."
            return 0
        elif [[ "${selection,,}" == "l" ]]; then
            selected_backup=$(find_latest_backup) || { press_enter_to_continue; return 0; }
            log "INFO" "Using latest backup: $(basename "${selected_backup}")"
        else
            if ! [[ "${selection}" =~ ^[0-9]+$ ]] || [[ "${selection}" -ge "${#BACKUPS_ARRAY[@]}" ]]; then
                log "ERROR" "Invalid selection: ${selection}"
                press_enter_to_continue
                return 0
            fi
            selected_backup="${BACKUPS_ARRAY[$selection]}"
        fi
    fi
    
    local backup_filename=$(basename "${selected_backup}")
    printf "\n"
    print_warning "You are about to restore from backup: ${backup_filename}"
    print_warning "This will OVERWRITE your current Pangolin configuration!"
    print_warning "Make sure the Pangolin stack is not running before proceeding."
    printf "\n"
    printf "${YELLOW}Are you ABSOLUTELY SURE you want to proceed? (Type 'YES' to confirm):${NC}\n"
    local confirmation
    read -r confirmation
    [[ "${confirmation^^}" != "YES" ]] && { log "INFO" "Restore cancelled by user."; return 0; }
    
    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "DRY-RUN: Would restore from backup: ${backup_filename}"
        log "SUCCESS" "DRY-RUN: Restore simulation completed successfully"
        return 0
    fi
    
    if docker_compose ps 2>/dev/null | grep -q "Up"; then
        log "WARNING" "Pangolin stack appears to be running."
        printf "${YELLOW}Do you want to stop the stack before restoring? (y/n/c):${NC}\n"
        local stop_stack
        read -r stop_stack
        if [[ "${stop_stack,,}" == "c" ]]; then
            log "INFO" "Restore cancelled by user."
            return 0
        elif [[ "${stop_stack,,}" == "y" ]]; then
            log "INFO" "Stopping Pangolin stack..."
            graceful_shutdown || { log "ERROR" "Failed to stop the stack."; press_enter_to_continue; return 0; }
        else
            log "WARNING" "Proceeding with restore while stack is running."
        fi
    fi
    
    local temp_dir=$(mktemp -d) || { log "ERROR" "Failed to create temporary directory."; press_enter_to_continue; return 0; }
    log "INFO" "Extracting backup..."
    tar -xzf "${selected_backup}" -C "${temp_dir}" || { log "ERROR" "Failed to extract backup archive."; rm -rf "${temp_dir}" 2>/dev/null || true; press_enter_to_continue; return 0; }
    
    local extracted_dir=$(find "${temp_dir}" -mindepth 1 -maxdepth 1 -type d | head -1)
    [[ -z "${extracted_dir}" ]] && { log "ERROR" "Failed to find extracted directory."; rm -rf "${temp_dir}" 2>/dev/null || true; press_enter_to_continue; return 0; }
    
    local current_backup_dir="${BACKUP_DIR}/pre_restore_${BACKUP_TIMESTAMP}"
    mkdir -p "${current_backup_dir}" || { log "ERROR" "Failed to create directory for current configuration backup."; rm -rf "${temp_dir}" 2>/dev/null || true; press_enter_to_continue; return 0; }
    
    log "INFO" "Creating backup of current configuration before restore..."
    for item in "${BACKUP_ITEMS[@]}"; do
        local source_path="${PANGOLIN_DIR}/${item}"
        if [[ -e "${source_path}" ]]; then
            mkdir -p "${current_backup_dir}/$(dirname "${item}")" || continue
            cp -a "${source_path}" "${current_backup_dir}/$(dirname "${item}")/" && log "INFO" "Backed up current: ${item}" || log "WARNING" "Failed to backup current: ${item}"
        fi
    done
    
    tar -czf "${current_backup_dir}.tar.gz" -C "${BACKUP_DIR}" "pre_restore_${BACKUP_TIMESTAMP}" || { log "ERROR" "Failed to create archive of current configuration."; rm -rf "${current_backup_dir}" "${temp_dir}" 2>/dev/null || true; press_enter_to_continue; return 0; }
    rm -rf "${current_backup_dir}" 2>/dev/null || true
    log "SUCCESS" "Created backup of current configuration: ${current_backup_dir}.tar.gz"
    
    log "INFO" "Restoring files from backup..."
    while IFS= read -r item_path; do
        local item=$(basename "${item_path}")
        [[ "${item}" == "BACKUP_INFO.txt" ]] && continue
        local source_path="${extracted_dir}/${item}"
        local dest_path="${PANGOLIN_DIR}/${item}"
        
        if [[ -e "${dest_path}" ]]; then
            log "INFO" "Removing existing: ${dest_path}"
            rm -rf "${dest_path}" || { log "ERROR" "Failed to remove existing item: ${dest_path}"; log "INFO" "Restore incomplete. Use: ${current_backup_dir}.tar.gz"; rm -rf "${temp_dir}" 2>/dev/null || true; press_enter_to_continue; return 0; }
        fi
        
        mkdir -p "$(dirname "${dest_path}")" || { log "ERROR" "Failed to create directory structure for: ${item}"; log "INFO" "Restore incomplete. Use: ${current_backup_dir}.tar.gz"; rm -rf "${temp_dir}" 2>/dev/null || true; press_enter_to_continue; return 0; }
        cp -a "${source_path}" "${dest_path}" || { log "ERROR" "Failed to restore item: ${item}"; log "INFO" "Restore incomplete. Use: ${current_backup_dir}.tar.gz"; rm -rf "${temp_dir}" 2>/dev/null || true; press_enter_to_continue; return 0; }
        log "INFO" "Restored: ${item}"
    done < <(find "${extracted_dir}" -mindepth 1 -maxdepth 1 -not -name "BACKUP_INFO.txt")
    
    rm -rf "${temp_dir}" 2>/dev/null || true
    log "SUCCESS" "Restore completed successfully."
    
    printf "${YELLOW}Do you want to start the Pangolin stack now? (y/n):${NC}\n"
    local start_stack
    read -r start_stack
    if [[ "${start_stack,,}" == "y" ]]; then
        log "INFO" "Starting Pangolin stack..."
        docker_compose up -d || { log "ERROR" "Failed to start Pangolin stack."; press_enter_to_continue; return 0; }
        log "SUCCESS" "Pangolin stack started successfully."
    else
        log "INFO" "Pangolin stack not started."
    fi
    return 0
}

########################
# UPDATE FUNCTIONS
########################

# Graceful service shutdown
graceful_shutdown() {
    log "INFO" "Starting graceful shutdown of services..."
    docker_compose stop -t 30 || log "WARNING" "Graceful stop failed, forcing shutdown..."
    docker_compose down --timeout 30 || { log "ERROR" "Failed to shut down services"; return 1; }
    docker_compose ps | grep -q "Up" && { log "ERROR" "Some services still running after shutdown"; return 1; }
    log "INFO" "Services stopped successfully"
    return 0
}

# Extract current image tags with more flexible pattern matching
extract_tag() {
    local service_name=$1
    local image_name=$2
    local tag=""
    local in_service=false
    local service_pattern="^  ${service_name}:"

    while IFS= read -r line; do
        if [[ "${line}" =~ ${service_pattern} ]]; then
            in_service=true
        elif [[ "${in_service}" == true && "${line}" =~ ^[[:space:]]{2}[a-z] ]]; then
            # Next service or end of services
            break
        elif [[ "${in_service}" == true && "${line}" =~ image:[[:space:]]*${image_name}: ]]; then
            # Extract the tag after the last colon
            tag=$(echo "${line}" | sed -n 's/.*:\([^:]*\)$/\1/p')
            break
        fi
    done < "${DOCKER_COMPOSE_FILE}"

    if [[ -z "${tag}" ]]; then
        log "WARNING" "Could not extract tag for '${image_name}' in service '${service_name}', using 'latest'"
        tag="latest"
    fi

    printf "%s" "${tag}"
    return 0
}

# Get current tags
get_current_tags() {
    log "INFO" "Reading current image tags..."

    if [[ ! -f "${DOCKER_COMPOSE_FILE}" ]]; then
        log "ERROR" "Docker compose file not found: ${DOCKER_COMPOSE_FILE}"
        PANGOLIN_CURRENT="latest"
        GERBIL_CURRENT="latest"
        TRAEFIK_CURRENT="latest"
        [[ "${INCLUDE_CROWDSEC}" == true ]] && CROWDSEC_CURRENT="latest"
        return 0
    fi

    # Extract tags using improved extract_tag function
    PANGOLIN_CURRENT=$(extract_tag "pangolin" "fosrl/pangolin")
    log "INFO" "Found Pangolin tag: ${PANGOLIN_CURRENT}"

    GERBIL_CURRENT=$(extract_tag "gerbil" "fosrl/gerbil")
    log "INFO" "Found Gerbil tag: ${GERBIL_CURRENT}"

    TRAEFIK_CURRENT=$(extract_tag "traefik" "traefik")
    log "INFO" "Found Traefik tag: ${TRAEFIK_CURRENT}"

    if [[ "${INCLUDE_CROWDSEC}" == true ]]; then
        CROWDSEC_CURRENT=$(extract_tag "crowdsec" "crowdsecurity/crowdsec")
        log "INFO" "Found CrowdSec tag: ${CROWDSEC_CURRENT}"
    fi
    return 0
}

# Interactive tag selection with improved user experience
get_new_tags() {
    log "INFO" "Requesting new image tags from user..."
    
    printf "\n${CYAN}Current versions:${NC}\n"
    printf "${CYAN}------------------------${NC}\n"
    printf "${CYAN}Pangolin tag:${NC} ${YELLOW}%s${NC}\n" "${PANGOLIN_CURRENT}"
    printf "Enter new Pangolin tag (or press enter to keep current, 'c' to cancel): "
    local new_tag
    read -r new_tag
    [[ "${new_tag,,}" == "c" ]] && { log "INFO" "Update cancelled by user."; OPERATION_CANCELLED=true; return 0; }
    PANGOLIN_NEW=${new_tag:-${PANGOLIN_CURRENT}}
    
    printf "${CYAN}Gerbil tag:${NC} ${YELLOW}%s${NC}\n" "${GERBIL_CURRENT}"
    printf "Enter new Gerbil tag (or press enter to keep current, 'c' to cancel): "
    read -r new_tag
    [[ "${new_tag,,}" == "c" ]] && { log "INFO" "Update cancelled by user."; OPERATION_CANCELLED=true; return 0; }
    GERBIL_NEW=${new_tag:-${GERBIL_CURRENT}}
    
    printf "${CYAN}Traefik tag:${NC} ${YELLOW}%s${NC}\n" "${TRAEFIK_CURRENT}"
    printf "Enter new Traefik tag (or press enter to keep current, 'c' to cancel): "
    read -r new_tag
    [[ "${new_tag,,}" == "c" ]] && { log "INFO" "Update cancelled by user."; OPERATION_CANCELLED=true; return 0; }
    TRAEFIK_NEW=${new_tag:-${TRAEFIK_CURRENT}}
    
    if [[ "${INCLUDE_CROWDSEC}" == true ]]; then
        printf "${CYAN}CrowdSec tag:${NC} ${YELLOW}%s${NC}\n" "${CROWDSEC_CURRENT}"
        printf "Enter new CrowdSec tag (or press enter to keep current, 'c' to cancel): "
        read -r new_tag
        [[ "${new_tag,,}" == "c" ]] && { log "INFO" "Update cancelled by user."; OPERATION_CANCELLED=true; return 0; }
        CROWDSEC_NEW=${new_tag:-${CROWDSEC_CURRENT}}
    fi
    
    printf "\n${CYAN}Summary of changes:${NC}\n"
    printf "${CYAN}------------------------${NC}\n"
    printf "Pangolin: ${YELLOW}%s${NC} -> ${GREEN}%s${NC}\n" "${PANGOLIN_CURRENT}" "${PANGOLIN_NEW}"
    printf "Gerbil: ${YELLOW}%s${NC} -> ${GREEN}%s${NC}\n" "${GERBIL_CURRENT}" "${GERBIL_NEW}"
    printf "Traefik: ${YELLOW}%s${NC} -> ${GREEN}%s${NC}\n" "${TRAEFIK_CURRENT}" "${TRAEFIK_NEW}"
    [[ "${INCLUDE_CROWDSEC}" == true ]] && printf "CrowdSec: ${YELLOW}%s${NC} -> ${GREEN}%s${NC}\n" "${CROWDSEC_CURRENT}" "${CROWDSEC_NEW}"
    printf "${CYAN}------------------------${NC}\n"
    
    printf "Proceed with these changes? (y/N/c): "
    local confirm
    read -r confirm
    if [[ "${confirm,,}" == "c" || ! "${confirm,,}" =~ ^y$ ]]; then
        log "INFO" "Update cancelled by user"
        OPERATION_CANCELLED=true
        return 0
    fi
    return 0
}

# Create backup for update
create_update_backup() {
    local update_backup_dir="${BACKUP_DIR}/update_${BACKUP_TIMESTAMP}"
    local archive_path="${update_backup_dir}.tar.gz"
    
    log "INFO" "Creating backup before update..."
    mkdir -p "${update_backup_dir}" || { log "ERROR" "Failed to create update backup directory: ${update_backup_dir}"; return 1; }
    grep "image:" "${DOCKER_COMPOSE_FILE}" > "${update_backup_dir}/old_tags.txt" 2>/dev/null || log "WARNING" "Failed to save current image tags, but continuing"
    [[ -d "./config" ]] && cp -r "./config" "${update_backup_dir}/" || log "WARNING" "Failed to backup config directory, but continuing"
    cp "${DOCKER_COMPOSE_FILE}" "${update_backup_dir}/" || { log "ERROR" "Failed to backup docker-compose.yml"; rm -rf "${update_backup_dir}" 2>/dev/null || true; return 1; }
    
    tar -czf "${archive_path}" -C "${BACKUP_DIR}" "update_${BACKUP_TIMESTAMP}" || { log "ERROR" "Failed to create backup archive: ${archive_path}"; rm -rf "${update_backup_dir}" 2>/dev/null || true; return 1; }
    rm -rf "${update_backup_dir}" 2>/dev/null || true
    log "SUCCESS" "Update backup created successfully: ${archive_path}"
    return 0
}

# Update service image in docker-compose.yml with improved pattern matching
update_service_image() {
    local service_name=$1
    local image_name=$2
    local current_tag=$3
    local new_tag=$4
    local file=$5
    
    if [[ "${current_tag}" == "${new_tag}" ]]; then
        log "INFO" "No change needed for ${service_name} (${current_tag})"
        return 0
    fi
    
    # Create a temporary file
    local tmp_file=$(mktemp)
    local update_successful=false
    local in_service=false
    local service_pattern="^  ${service_name}:"
    
    # Process the file line by line for more precise control
    while IFS= read -r line; do
        # Check if we're in the target service section
        if [[ "${line}" =~ ${service_pattern} ]]; then
            in_service=true
        elif [[ "${in_service}" == true && "${line}" =~ ^[[:space:]]{2}[a-z] ]]; then
            # We've reached the next service, reset the flag
            in_service=false
        fi
        
        # If we're in the target service and this is the image line
        if [[ "${in_service}" == true && "${line}" =~ image:[[:space:]]*${image_name}:${current_tag} ]]; then
            # Replace the tag
            echo "${line//:${current_tag}/:${new_tag}}" >> "${tmp_file}"
            update_successful=true
            log "SUCCESS" "Updated ${service_name}: ${current_tag} -> ${new_tag}"
        else
            # Write the line unchanged
            echo "${line}" >> "${tmp_file}"
        fi
    done < "${file}"
    
    if [[ "${update_successful}" == true ]]; then
        mv "${tmp_file}" "${file}" || { 
            log "ERROR" "Failed to update ${file} for ${service_name}"
            rm -f "${tmp_file}" 2>/dev/null || true
            return 1
        }
    else
        log "WARNING" "Pattern not found for ${service_name} with ${image_name}:${current_tag}"
        rm -f "${tmp_file}" 2>/dev/null || true
        
        # Try a more flexible approach if exact match failed
        log "INFO" "Attempting flexible pattern matching for ${service_name}..."
        
        local tmp_file2=$(mktemp)
        local update_successful2=false
        local in_service=false
        
        while IFS= read -r line; do
            # Check if we're in the target service section
            if [[ "${line}" =~ ${service_pattern} ]]; then
                in_service=true
            elif [[ "${in_service}" == true && "${line}" =~ ^[[:space:]]{2}[a-z] ]]; then
                # We've reached the next service, reset the flag
                in_service=false
            fi
            
            # If we're in the target service and this is an image line
            if [[ "${in_service}" == true && "${line}" =~ image:[[:space:]]*${image_name}: ]]; then
                # Replace with new tag, regardless of current tag
                echo "    image: ${image_name}:${new_tag}" >> "${tmp_file2}"
                update_successful2=true
                log "SUCCESS" "Updated ${service_name} with flexible matching: -> ${new_tag}"
            else
                # Write the line unchanged
                echo "${line}" >> "${tmp_file2}"
            fi
        done < "${file}"
        
        if [[ "${update_successful2}" == true ]]; then
            mv "${tmp_file2}" "${file}" || { 
                log "ERROR" "Failed to update ${file} for ${service_name} with flexible matching"
                rm -f "${tmp_file2}" 2>/dev/null || true
                return 1
            }
        else
            log "ERROR" "Could not update image tag for ${service_name} even with flexible matching"
            rm -f "${tmp_file2}" 2>/dev/null || true
            return 1
        fi
    fi
    
    return 0
}

# Update service images with improved error handling
update_images() {
    log "INFO" "Starting update process..."
    
    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "DRY-RUN: Would update image tags in docker-compose.yml"
        log "SUCCESS" "DRY-RUN: Update simulation completed successfully"
        return 0
    fi
    
    if [[ ! -f "${DOCKER_COMPOSE_FILE}" || ! -w "${DOCKER_COMPOSE_FILE}" ]]; then
        log "ERROR" "Docker compose file not found or not writable: ${DOCKER_COMPOSE_FILE}"
        printf "${YELLOW}Enter the path to your docker-compose.yml file (or 'c' to cancel):${NC} "
        local response
        read -r response
        [[ "${response,,}" == "c" ]] && { log "INFO" "Update cancelled by user."; return 1; }
        DOCKER_COMPOSE_FILE="${response}"
        [[ ! -f "${DOCKER_COMPOSE_FILE}" || ! -w "${DOCKER_COMPOSE_FILE}" ]] && { log "ERROR" "Invalid file: ${DOCKER_COMPOSE_FILE}"; return 1; }
    fi
    
    # Create a backup of docker-compose.yml
    cp "${DOCKER_COMPOSE_FILE}" "${DOCKER_COMPOSE_FILE}.bak" || { 
        log "ERROR" "Failed to create backup of docker-compose.yml" 
        return 1
    }
    log "INFO" "Created backup of docker-compose.yml at ${DOCKER_COMPOSE_FILE}.bak"
    
    local max_attempts=3
    local attempt=1
    local shutdown_success=false
    while [[ ${attempt} -le ${max_attempts} && "${shutdown_success}" == false ]]; do
        graceful_shutdown && shutdown_success=true || { log "WARNING" "Shutdown attempt ${attempt}/${max_attempts} failed. Retrying..."; sleep 5; ((attempt++)); }
    done
    [[ "${shutdown_success}" == false ]] && { log "ERROR" "Failed to shutdown services after ${max_attempts} attempts."; return 1; }
    
    # Update image tags in docker-compose.yml
    local update_successful=true
    
    update_service_image "pangolin" "fosrl/pangolin" "${PANGOLIN_CURRENT}" "${PANGOLIN_NEW}" "${DOCKER_COMPOSE_FILE}" || update_successful=false
    update_service_image "gerbil" "fosrl/gerbil" "${GERBIL_CURRENT}" "${GERBIL_NEW}" "${DOCKER_COMPOSE_FILE}" || update_successful=false
    update_service_image "traefik" "traefik" "${TRAEFIK_CURRENT}" "${TRAEFIK_NEW}" "${DOCKER_COMPOSE_FILE}" || update_successful=false
    
    if [[ "${INCLUDE_CROWDSEC}" == true ]]; then
        update_service_image "crowdsec" "crowdsecurity/crowdsec" "${CROWDSEC_CURRENT}" "${CROWDSEC_NEW}" "${DOCKER_COMPOSE_FILE}" || update_successful=false
    fi
    
    if [[ "${update_successful}" == false ]]; then
        printf "${YELLOW}Some updates failed. Continue anyway? (y/n/c):${NC} "
        local response
        read -r response
        if [[ "${response,,}" == "c" || "${response,,}" != "y" ]]; then
            log "INFO" "Restoring docker-compose.yml from backup..."
            mv "${DOCKER_COMPOSE_FILE}.bak" "${DOCKER_COMPOSE_FILE}" || log "ERROR" "Failed to restore docker-compose.yml from backup!"
            log "INFO" "Update cancelled by user"
            return 1
        fi
    fi
    
    # Pull new images selectively based on include_crowdsec flag
    log "INFO" "Pulling new images..."
    if [[ "${INCLUDE_CROWDSEC}" == true ]]; then
        docker_compose pull || {
            log "WARNING" "Failed to pull some images"
            printf "${YELLOW}Some images failed to pull. Continue anyway? (y/n/c):${NC} "
            local response
            read -r response
            [[ "${response,,}" == "c" || "${response,,}" != "y" ]] && { log "INFO" "Update cancelled by user"; return 1; }
        }
    else
        # Skip CrowdSec when pulling if not included
        docker_compose pull pangolin gerbil traefik || {
            log "WARNING" "Failed to pull some images"
            printf "${YELLOW}Some images failed to pull. Continue anyway? (y/n/c):${NC} "
            local response
            read -r response
            [[ "${response,,}" == "c" || "${response,,}" != "y" ]] && { log "INFO" "Update cancelled by user"; return 1; }
        }
    fi
    
    log "INFO" "Starting updated stack..."
    docker_compose up -d || { 
        log "ERROR" "Failed to start updated stack"
        printf "${YELLOW}Failed to start the stack. Would you like to restore from backup? (y/n):${NC} "
        local response
        read -r response
        if [[ "${response,,}" == "y" ]]; then
            log "INFO" "Restoring docker-compose.yml from backup..."
            mv "${DOCKER_COMPOSE_FILE}.bak" "${DOCKER_COMPOSE_FILE}" || log "ERROR" "Failed to restore docker-compose.yml from backup!"
            log "INFO" "Attempting to start with original configuration..."
            docker_compose up -d || log "ERROR" "Failed to start stack with original configuration"
        fi
        return 1
    }
    
    # Remove the backup file if everything was successful
    rm -f "${DOCKER_COMPOSE_FILE}.bak" 2>/dev/null || log "WARNING" "Failed to remove backup file: ${DOCKER_COMPOSE_FILE}.bak"
    
    log "INFO" "Waiting for services to start..."
    local max_attempts=12
    local attempt=1
    local all_up=false
    while [[ ${attempt} -le ${max_attempts} && "${all_up}" == false ]]; do
        printf "Checking service status (attempt %d/%d)...\n" "${attempt}" "${max_attempts}"
        sleep 5
        verify_services && all_up=true || ((attempt++))
    done
    
    if [[ "${all_up}" == true ]]; then
        log "SUCCESS" "Services have been updated successfully"
        docker_compose ps
        return 0
    else
        log "WARNING" "Not all services are running after update"
        docker_compose ps
        return 1
    fi
}

# Update with CrowdSec
update_with_crowdsec() {
    print_header "UPDATE PANGOLIN STACK (WITH CROWDSEC)"
    INCLUDE_CROWDSEC=true
    SERVICES=("${SERVICES_WITH_CROWDSEC[@]}")
    OPERATION_CANCELLED=false
    
    create_update_backup || return 1
    get_current_tags || return 1
    get_new_tags
    [[ "${OPERATION_CANCELLED}" == true ]] && { press_enter_to_continue; return 0; }
    update_images || return 1
    log "SUCCESS" "Pangolin stack (with CrowdSec) has been updated successfully"
    return 0
}

# Update without CrowdSec
update_without_crowdsec() {
    print_header "UPDATE PANGOLIN STACK (WITHOUT CROWDSEC)"
    INCLUDE_CROWDSEC=false
    SERVICES=("${SERVICES_BASIC[@]}")
    OPERATION_CANCELLED=false
    
    create_update_backup || return 1
    get_current_tags || return 1
    get_new_tags
    [[ "${OPERATION_CANCELLED}" == true ]] && { press_enter_to_continue; return 0; }
    update_images || return 1
    log "SUCCESS" "Pangolin stack (without CrowdSec) has been updated successfully"
    return 0
}

# Setup cron job

setup_cron_job() {
    print_header "CRON JOB SETUP"
    local cron_script_path=$(readlink -f "${SCRIPT_DIR}/master.sh")
    
    # Check if crontab is installed
    if ! command -v crontab &> /dev/null; then
        print_error "The 'crontab' command was not found on this system."
        print_info "You need to install cron to use this feature:"
        print_info "  - For Debian/Ubuntu: sudo apt-get update && sudo apt-get install cron"
        print_info "  - For CentOS/RHEL: sudo yum install cronie"
        print_info "  - For Alpine: apk add dcron"
        print_info "After installation, you may need to enable and start the cron service:"
        print_info "  - systemctl enable cron && systemctl start cron (for systemd-based systems)"
        press_enter_to_continue
        return 1
    fi
    
    printf "${CYAN}This will setup a cron job to automatically run backups.${NC}\n\n"
    printf "${CYAN}Current cron jobs for this script:${NC}\n"
    local current_cron=$(crontab -l 2>/dev/null | grep -F "master.sh" || true)
    [[ -n "$current_cron" ]] && printf "%s\n" "$current_cron" || printf "  No cron jobs found.\n"
    printf "\n${CYAN}Schedule Options:${NC}\n"
    printf "1. Daily (at midnight)\n"
    printf "2. Every 3 days (at midnight)\n"
    printf "3. Weekly (Sunday at midnight)\n"
    printf "4. Custom schedule\n"
    printf "5. Remove existing cron job\n"
    printf "6. Cancel\n\n"
    printf "Enter your choice [1-6]: "
    local choice
    read -r choice
    
    case "${choice}" in
        1) local schedule="0 0 * * *" description="daily at midnight" ;;
        2) local schedule="0 0 */3 * *" description="every 3 days at midnight" ;;
        3) local schedule="0 0 * * 0" description="weekly on Sunday at midnight" ;;
        4)
            printf "Enter cron schedule expression (e.g., '0 2 */3 * *') or 'c' to cancel: "
            local custom_schedule
            read -r custom_schedule
            [[ "${custom_schedule,,}" == "c" || -z "${custom_schedule}" ]] && { log "INFO" "Cron job setup cancelled."; return 0; }
            schedule="${custom_schedule}"
            description="custom schedule: ${schedule}"
            ;;
        5)
            if [[ "${DRY_RUN}" == true ]]; then
                log "INFO" "DRY-RUN: Would remove cron job for pangolin-backup.sh"
            else
                local temp_crontab=$(mktemp) || { log "ERROR" "Failed to create temporary file."; return 1; }
                crontab -l > "${temp_crontab}.orig" 2>/dev/null || touch "${temp_crontab}"
                grep -v "master.sh" "${temp_crontab}.orig" > "${temp_crontab}" || true
                diff "${temp_crontab}.orig" "${temp_crontab}" >/dev/null && log "INFO" "No matching cron jobs found to remove" || { crontab "${temp_crontab}" && log "SUCCESS" "Removed cron job(s) for pangolin-backup.sh" || { log "ERROR" "Failed to update crontab"; rm -f "${temp_crontab}" "${temp_crontab}.orig" 2>/dev/null || true; return 1; }; }
                rm -f "${temp_crontab}" "${temp_crontab}.orig" 2>/dev/null || true
            fi
            # Removal code stays the same, using cron_script_path instead of script_path
            return 0
            ;;
        6) log "INFO" "Cron job setup cancelled."; return 0 ;;
        *) log "ERROR" "Invalid choice."; return 1 ;;
    esac
    
    printf "\n${YELLOW}This will setup a cron job to run %s.${NC}\n" "${description}"
    printf "${YELLOW}Cron schedule: %s${NC}\n" "${schedule}"
    printf "${YELLOW}Command: %s --cron backup${NC}\n\n" "${script_path}"
    printf "Do you want to proceed? (y/n/c): "
    local confirm
    read -r confirm
    [[ "${confirm,,}" == "c" || "${confirm,,}" != "y" ]] && { log "INFO" "Cron job setup cancelled."; return 0; }
    
    if [[ "${DRY_RUN}" == true ]]; then
        log "INFO" "DRY-RUN: Would add cron job: ${schedule} ${script_path} --cron backup"
        return 0
    fi
    
    local temp_crontab=$(mktemp) || { log "ERROR" "Failed to create temporary file."; return 1; }
    crontab -l > "${temp_crontab}" 2>/dev/null || touch "${temp_crontab}"
    grep -v "master.sh" "${temp_crontab}" > "${temp_crontab}.new" || true
    mv "${temp_crontab}.new" "${temp_crontab}"
    printf "%s %s --cron backup\n" "${schedule}" "${script_path}" >> "${temp_crontab}"
    crontab "${temp_crontab}" && log "SUCCESS" "Cron job setup successfully for ${description}." || { log "ERROR" "Failed to setup cron job."; rm -f "${temp_crontab}" 2>/dev/null || true; return 1; }
    rm -f "${temp_crontab}" 2>/dev/null || true
    return 0
}

# Verify service status
verify_services() {
    log "INFO" "Verifying services status..."
    local service_status=$(docker_compose ps)
    log "INFO" "Current service status:"
    printf "%s\n" "${service_status}" | tee -a "${LOG_FILE}" >/dev/null 2>&1 || true
    
    local all_services_up=true
    local service_list=("${SERVICES[@]}")
    
    for service in "${service_list[@]}"; do
        docker_compose ps -q "${service}" 2>/dev/null | grep -q . || { log "ERROR" "Service ${service} does not exist"; all_services_up=false; continue; }
        docker_compose ps "${service}" 2>/dev/null | grep -q "Up" || { log "ERROR" "Service ${service} exists but is not running"; all_services_up=false; }
    done
    
    [[ "${all_services_up}" == false ]] && { log "ERROR" "Not all services are running"; return 1; }
    log "INFO" "All services are running"
    return 0
}

########################
# MENU AND PREREQUISITES
########################

# Check prerequisites
check_prerequisites() {
    print_header "CHECKING PREREQUISITES"
    
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    else
        print_success "Docker is running"
    fi
    
    if ! docker ps -a | grep -q crowdsec; then
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
    echo -e "${HEADER_LINE}"
    echo -e "${TITLE_LINE}"
    echo -e "${AUTHOR_LINE}"
    echo -e "${HEADER_LINE}"
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
    echo -e "${CYAN}16.${NC} Advanced Traefik Log Analysis"
    echo ""
    echo -e "${CYAN}BACKUP & UPDATE${NC}"
    echo -e "${CYAN}17.${NC} Create Backup"
    echo -e "${CYAN}18.${NC} Restore from Backup"
    echo -e "${CYAN}19.${NC} List Available Backups"
    echo -e "${CYAN}20.${NC} Delete Backups"
    echo -e "${CYAN}21.${NC} Update Stack (without CrowdSec)"
    echo -e "${CYAN}22.${NC} Update Stack (with CrowdSec)"
    echo -e "${CYAN}23.${NC} Setup Automatic Backup Cron Job"
    echo ""
    echo -e "${CYAN}0.${NC} Exit"
    echo ""
    echo -ne "${YELLOW}Enter your choice [0-23]:${NC} "
    read -r choice
    
    case $choice in
        1) check_stack_health; press_enter_to_continue ;;
        2) run_complete_check ;;
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
        16) analyze_traefik_logs_advanced ;;
        17) create_backup; press_enter_to_continue ;;
        18) restore_backup; press_enter_to_continue ;;
        19) list_backups; press_enter_to_continue ;;
        20) delete_backups; press_enter_to_continue ;;
        21) update_without_crowdsec; press_enter_to_continue ;;
        22) update_with_crowdsec; press_enter_to_continue ;;
        23) setup_cron_job; press_enter_to_continue ;;
        0) cleanup; exit 0 ;;
        *) echo -e "${RED}Invalid option. Please try again.${NC}"; press_enter_to_continue ;;
    esac
}

# Invoke main with args if not sourced
# Approach via: https://stackoverflow.com/a/28776166/8787985
if ! (return 0 2> /dev/null); then
    main "$@"
fi

# vim: syntax=sh cc=80 tw=79 ts=4 sw=4 sts=4 et sr