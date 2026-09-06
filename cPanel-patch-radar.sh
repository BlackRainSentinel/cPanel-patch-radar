#!/usr/bin/env bash
# =============================================================================
#  cpanel-patch-radar - cPanel/WHM CVE Audit & Remediation Tool
#  Author  : Danial Sobhani (@danial_hmt)
#  License : MIT
#  Version : 1.0.0
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants & Version
# ---------------------------------------------------------------------------
readonly VERSION="1.0.0"
readonly TOOL_NAME="cpanel-patch-radar"
readonly LOG_DIR="/var/log/cpanel-patch-radar"
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
readonly LOG_FILE="${LOG_DIR}/audit_${TIMESTAMP}.log"
readonly HTML_FILE="${LOG_DIR}/report_${TIMESTAMP}.html"
readonly CPANEL_VERSION_FILE="/usr/local/cpanel/version"
readonly CPANEL_SCRIPTS="/usr/local/cpanel/scripts"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
FLAG_FIX=false
FLAG_REPORT=false
FLAG_BACKUP=false
FLAG_QUIET=false
FLAG_SPECIFIC_CVE=""

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
TOTAL_CHECKS=0
PASSED=0
FAILED=0
WARNED=0
FIXED=0

# ---------------------------------------------------------------------------
# CVE Database
# ---------------------------------------------------------------------------
declare -A CVE_PACKAGES=(
    ["CVE-2026-41940"]="cpanel"
    ["CVE-2026-9256"]="ea-nginx"
    ["CVE-2026-33278"]="cpanel-unbound"
    ["CVE-2026-32993"]="cpanel"
    ["CVE-2026-32992"]="cpanel"
    ["CVE-2026-32991"]="cpanel"
    ["CVE-2026-29206"]="cpanel"
    ["CVE-2026-29205"]="cpanel"
    ["SEC-73755"]="cpanel"
    ["SEC-73728"]="cpanel"
    ["EASERVER-v25.62"]="ea-apache24"
    ["LITESPEED-AUTO-REMOVE"]="ea-lsws"
)

declare -A CVE_DESCRIPTIONS=(
    ["CVE-2026-41940"]="cPanel & WHM Authentication Bypass (Critical)"
    ["CVE-2026-9256"]="ea-nginx v1.31.1 Security Release"
    ["CVE-2026-33278"]="cpanel-unbound 1.25.1 Security Release"
    ["CVE-2026-32993"]="cPanel & WHM / WP2 Security Update"
    ["CVE-2026-32992"]="cPanel & WHM / WP2 Security Update"
    ["CVE-2026-32991"]="cPanel & WHM / WP2 Security Update"
    ["CVE-2026-29206"]="cPanel & WHM / WP2 Security Update"
    ["CVE-2026-29205"]="cPanel & WHM / WP2 Security Update"
    ["SEC-73755"]="cPanel & WHM / WP2 Security Update"
    ["SEC-73728"]="cPanel & WHM / WP2 Security Update"
    ["EASERVER-v25.62"]="EasyApache4 v25.62 Security Release"
    ["LITESPEED-AUTO-REMOVE"]="LiteSpeed Plugin Auto-Removal on Nightly Update"
)

declare -A CVE_SEVERITY=(
    ["CVE-2026-41940"]="CRITICAL"
    ["CVE-2026-9256"]="HIGH"
    ["CVE-2026-33278"]="HIGH"
    ["CVE-2026-32993"]="HIGH"
    ["CVE-2026-32992"]="HIGH"
    ["CVE-2026-32991"]="MEDIUM"
    ["CVE-2026-29206"]="HIGH"
    ["CVE-2026-29205"]="HIGH"
    ["SEC-73755"]="HIGH"
    ["SEC-73728"]="HIGH"
    ["EASERVER-v25.62"]="MEDIUM"
    ["LITESPEED-AUTO-REMOVE"]="INFO"
)

declare -A CVE_FIX_DATE=(
    ["CVE-2026-41940"]="2026-05-10"
    ["CVE-2026-9256"]="2026-05-22"
    ["CVE-2026-33278"]="2026-05-21"
    ["CVE-2026-32993"]="2026-05-13"
    ["CVE-2026-32992"]="2026-05-13"
    ["CVE-2026-32991"]="2026-05-13"
    ["CVE-2026-29206"]="2026-05-13"
    ["CVE-2026-29205"]="2026-05-13"
    ["SEC-73755"]="2026-05-19"
    ["SEC-73728"]="2026-05-19"
    ["EASERVER-v25.62"]="2026-05-21"
    ["LITESPEED-AUTO-REMOVE"]="2026-05-19"
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_to_file() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}" >> "${LOG_FILE}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Print Helpers
# ---------------------------------------------------------------------------
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
   ___  ____  __   ____  ____  __       ____  __  ____  ____  _  _     ____  __   ____   __   ____
  / __)(  _ \/ _\ (  _ \(  __)(  )     (  _ \/ _\(_  _)/ ___\/ )( \   (  _ \/ _\ (    \ / _\ (  _ \
 ( (__  ) __/    \ ) __/ ) _)  ) (_/\   ) __/    \  )(  \___ \) __ (    )   /    \ ) D (    \  )   /
  \___)(__)  \_/\_/(__)  (____)(_____/  (__)  \_/\_/(__) (____/\_)(_/   (__\_)\_/\_/(____/\_/\_(__\_)
EOF
    echo -e "${RESET}"
    echo -e "${DIM}  cPanel/WHM CVE Audit & Remediation Tool — v${VERSION}${RESET}"
    echo -e "${DIM}  by Danial Sobhani (@danial_hmt)${RESET}"
    echo ""
}

print_separator() {
    echo -e "${DIM}$(printf '─%.0s' {1..72})${RESET}"
}

print_section() {
    local title="$1"
    echo ""
    print_separator
    echo -e "  ${BOLD}${BLUE}▶  ${title}${RESET}"
    print_separator
}

print_result() {
    local status="$1"
    local cve="$2"
    local message="$3"
    local severity="${4:-}"

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    local severity_badge=""
    case "${severity}" in
        CRITICAL) severity_badge="${RED}[CRITICAL]${RESET}" ;;
        HIGH)     severity_badge="${YELLOW}[HIGH]    ${RESET}" ;;
        MEDIUM)   severity_badge="${MAGENTA}[MEDIUM]  ${RESET}" ;;
        INFO)     severity_badge="${CYAN}[INFO]    ${RESET}" ;;
        *)        severity_badge="          " ;;
    esac

    case "${status}" in
        PASS)
            PASSED=$((PASSED + 1))
            echo -e "  ${GREEN}✔ PASS${RESET}  ${severity_badge}  ${WHITE}${cve}${RESET}"
            echo -e "         ${DIM}${message}${RESET}"
            log_to_file "PASS" "${cve}: ${message}"
            ;;
        FAIL)
            FAILED=$((FAILED + 1))
            echo -e "  ${RED}✘ FAIL${RESET}  ${severity_badge}  ${WHITE}${cve}${RESET}"
            echo -e "         ${DIM}${message}${RESET}"
            log_to_file "FAIL" "${cve}: ${message}"
            ;;
        WARN)
            WARNED=$((WARNED + 1))
            echo -e "  ${YELLOW}⚠ WARN${RESET}  ${severity_badge}  ${WHITE}${cve}${RESET}"
            echo -e "         ${DIM}${message}${RESET}"
            log_to_file "WARN" "${cve}: ${message}"
            ;;
        FIXED)
            FIXED=$((FIXED + 1))
            echo -e "  ${CYAN}↺ FIXED${RESET} ${severity_badge}  ${WHITE}${cve}${RESET}"
            echo -e "         ${DIM}${message}${RESET}"
            log_to_file "FIXED" "${cve}: ${message}"
            ;;
        SKIP)
            echo -e "  ${GRAY}○ SKIP${RESET}  ${severity_badge}  ${GRAY}${cve}${RESET}"
            echo -e "         ${DIM}${message}${RESET}"
            log_to_file "SKIP" "${cve}: ${message}"
            ;;
    esac
    echo ""
}

print_info() {
    echo -e "  ${CYAN}ℹ${RESET}  $*"
}

print_warn() {
    echo -e "  ${YELLOW}⚠${RESET}  $*"
}

print_error() {
    echo -e "  ${RED}✘${RESET}  $*" >&2
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo -e "  bash ${TOOL_NAME}.sh [OPTIONS]"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo -e "  ${CYAN}--fix${RESET}              Attempt to fix vulnerable packages (requires confirmation)"
    echo -e "  ${CYAN}--report${RESET}           Generate HTML report in ${LOG_DIR}/"
    echo -e "  ${CYAN}--backup${RESET}           Create backups before applying fixes"
    echo -e "  ${CYAN}--cve <ID>${RESET}         Audit a single CVE only (e.g. --cve CVE-2026-41940)"
    echo -e "  ${CYAN}--quiet${RESET}            Suppress banner and informational output"
    echo -e "  ${CYAN}--version${RESET}          Show version"
    echo -e "  ${CYAN}--help${RESET}             Show this help"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo -e "  bash ${TOOL_NAME}.sh"
    echo -e "  bash ${TOOL_NAME}.sh --fix --backup"
    echo -e "  bash ${TOOL_NAME}.sh --fix --report"
    echo -e "  bash ${TOOL_NAME}.sh --cve CVE-2026-41940"
    echo -e "  bash ${TOOL_NAME}.sh --fix --report --backup"
    echo ""
}

# ---------------------------------------------------------------------------
# Prerequisite Checks
# ---------------------------------------------------------------------------
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        print_error "This tool must be run as root."
        exit 1
    fi
}

check_cpanel() {
    if [[ ! -f "${CPANEL_VERSION_FILE}" ]]; then
        print_error "cPanel installation not found. This tool is cPanel/WHM specific."
        exit 1
    fi
}

get_cpanel_version() {
    cat "${CPANEL_VERSION_FILE}" 2>/dev/null | tr -d '[:space:]' || echo "unknown"
}

get_package_version() {
    local pkg="$1"
    rpm -q --queryformat '%{VERSION}-%{RELEASE}' "${pkg}" 2>/dev/null || echo "not-installed"
}

setup_log_dir() {
    mkdir -p "${LOG_DIR}" || {
        print_error "Cannot create log directory: ${LOG_DIR}"
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Backup Helper
# ---------------------------------------------------------------------------
take_backup() {
    local target="$1"
    local backup_path="${LOG_DIR}/backup_${TIMESTAMP}"
    mkdir -p "${backup_path}"

    if [[ -f "${target}" ]]; then
        cp -p "${target}" "${backup_path}/" && \
            print_info "Backup created: ${backup_path}/$(basename "${target}")"
    elif [[ -d "${target}" ]]; then
        cp -rp "${target}" "${backup_path}/" && \
            print_info "Backup created: ${backup_path}/$(basename "${target}")"
    else
        print_warn "Nothing to backup at: ${target}"
    fi
    log_to_file "BACKUP" "Backed up: ${target} -> ${backup_path}"
}

# ---------------------------------------------------------------------------
# Confirmation Prompt
# ---------------------------------------------------------------------------
confirm() {
    local message="$1"
    echo -e ""
    echo -e "  ${YELLOW}${BOLD}? ${message}${RESET} ${DIM}[y/N]${RESET} "
    read -r -n1 answer
    echo ""
    [[ "${answer,,}" == "y" ]]
}

# ---------------------------------------------------------------------------
# Fix: Targeted Package Update
# ---------------------------------------------------------------------------
fix_package() {
    local pkg="$1"
    local cve_id="$2"

    if [[ "${FLAG_FIX}" == false ]]; then
        return 1
    fi

    if ! confirm "Apply targeted fix for ${cve_id} (package: ${pkg})?"; then
        print_info "Fix skipped by user."
        log_to_file "SKIP_FIX" "${cve_id}: user declined"
        return 1
    fi

    if [[ "${FLAG_BACKUP}" == true ]]; then
        take_backup "/etc/${pkg}.conf" 2>/dev/null || true
    fi

    print_info "Running: yum update -y ${pkg}"
    log_to_file "FIX_START" "${cve_id}: yum update ${pkg}"

    if yum update -y "${pkg}" >> "${LOG_FILE}" 2>&1; then
        log_to_file "FIX_OK" "${cve_id}: ${pkg} updated successfully"
        return 0
    else
        log_to_file "FIX_ERR" "${cve_id}: failed to update ${pkg}"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# CVE Check Functions
# ---------------------------------------------------------------------------

# CVE-2026-41940: cPanel Authentication Bypass (Critical)
check_CVE_2026_41940() {
    local cve="CVE-2026-41940"
    local desc="${CVE_DESCRIPTIONS[$cve]}"
    local severity="${CVE_SEVERITY[$cve]}"
    local pkg="${CVE_PACKAGES[$cve]}"

    local version
    version=$(get_cpanel_version)

    # Fixed in cPanel 120.0.14+ / 118.0.22+
    # Vulnerable: < 118.0.22 or between 119.x and 120.0.13
    local major minor patch
    major=$(echo "${version}" | cut -d. -f1)
    minor=$(echo "${version}" | cut -d. -f2)
    patch=$(echo "${version}" | cut -d. -f3)

    local is_vulnerable=false

    if [[ "${major}" -lt 118 ]]; then
        is_vulnerable=true
    elif [[ "${major}" -eq 118 && "${minor}" -eq 0 && "${patch}" -lt 22 ]]; then
        is_vulnerable=true
    elif [[ "${major}" -eq 119 ]]; then
        is_vulnerable=true
    elif [[ "${major}" -eq 120 && "${minor}" -eq 0 && "${patch}" -lt 14 ]]; then
        is_vulnerable=true
    fi

    if [[ "${is_vulnerable}" == true ]]; then
        print_result "FAIL" "${cve}" "${desc} — cPanel ${version} is vulnerable. Fix date: ${CVE_FIX_DATE[$cve]}" "${severity}"
        if fix_package "${pkg}" "${cve}"; then
            print_result "FIXED" "${cve}" "Package updated. Re-run audit to verify." "${severity}"
        fi
    else
        print_result "PASS" "${cve}" "${desc} — cPanel ${version} is patched." "${severity}"
    fi
}

# CVE-2026-9256: ea-nginx Security Release
check_CVE_2026_9256() {
    local cve="CVE-2026-9256"
    local desc="${CVE_DESCRIPTIONS[$cve]}"
    local severity="${CVE_SEVERITY[$cve]}"
    local pkg="${CVE_PACKAGES[$cve]}"

    local installed_version
    installed_version=$(get_package_version "${pkg}")

    if [[ "${installed_version}" == "not-installed" ]]; then
        print_result "SKIP" "${cve}" "${desc} — ea-nginx not installed on this server." "${severity}"
        return
    fi

    # Fixed in ea-nginx 1.31.1+
    local ver_only
    ver_only=$(echo "${installed_version}" | cut -d- -f1)
    local major minor patch
    major=$(echo "${ver_only}" | cut -d. -f1)
    minor=$(echo "${ver_only}" | cut -d. -f2)
    patch=$(echo "${ver_only}" | cut -d. -f3)

    if [[ "${major}" -lt 1 ]] || \
       [[ "${major}" -eq 1 && "${minor}" -lt 31 ]] || \
       [[ "${major}" -eq 1 && "${minor}" -eq 31 && "${patch}" -lt 1 ]]; then
        print_result "FAIL" "${cve}" "${desc} — Installed: ${installed_version}. Fix date: ${CVE_FIX_DATE[$cve]}" "${severity}"
        if fix_package "${pkg}" "${cve}"; then
            print_result "FIXED" "${cve}" "Package updated." "${severity}"
        fi
    else
        print_result "PASS" "${cve}" "${desc} — Installed: ${installed_version}" "${severity}"
    fi
}

# CVE-2026-33278: cpanel-unbound Security Release
check_CVE_2026_33278() {
    local cve="CVE-2026-33278"
    local desc="${CVE_DESCRIPTIONS[$cve]}"
    local severity="${CVE_SEVERITY[$cve]}"
    local pkg="${CVE_PACKAGES[$cve]}"

    local installed_version
    installed_version=$(get_package_version "${pkg}")

    if [[ "${installed_version}" == "not-installed" ]]; then
        print_result "SKIP" "${cve}" "${desc} — cpanel-unbound not installed." "${severity}"
        return
    fi

    # Fixed in 1.25.1+
    local ver_only
    ver_only=$(echo "${installed_version}" | cut -d- -f1)
    local major minor patch
    major=$(echo "${ver_only}" | cut -d. -f1)
    minor=$(echo "${ver_only}" | cut -d. -f2)
    patch=$(echo "${ver_only}" | cut -d. -f3)

    if [[ "${major}" -lt 1 ]] || \
       [[ "${major}" -eq 1 && "${minor}" -lt 25 ]] || \
       [[ "${major}" -eq 1 && "${minor}" -eq 25 && "${patch}" -lt 1 ]]; then
        print_result "FAIL" "${cve}" "${desc} — Installed: ${installed_version}. Fix date: ${CVE_FIX_DATE[$cve]}" "${severity}"
        if fix_package "${pkg}" "${cve}"; then
            print_result "FIXED" "${cve}" "Package updated." "${severity}"
        fi
    else
        print_result "PASS" "${cve}" "${desc} — Installed: ${installed_version}" "${severity}"
    fi
}

# CVE-2026-32993 / 32992 / 32991 / 29206 / 29205 — cPanel core updates
# SEC-73755 / SEC-73728 — cPanel core updates
check_cpanel_core_cves() {
    local cves=("CVE-2026-32993" "CVE-2026-32992" "CVE-2026-32991" "CVE-2026-29206" "CVE-2026-29205" "SEC-73755" "SEC-73728")

    local version
    version=$(get_cpanel_version)
    local major minor patch
    major=$(echo "${version}" | cut -d. -f1)
    minor=$(echo "${version}" | cut -d. -f2)
    patch=$(echo "${version}" | cut -d. -f3)

    # All fixed in cPanel 120.0.14+ / 118.0.22+
    local is_vulnerable=false
    if [[ "${major}" -lt 118 ]]; then
        is_vulnerable=true
    elif [[ "${major}" -eq 118 && "${minor}" -eq 0 && "${patch}" -lt 22 ]]; then
        is_vulnerable=true
    elif [[ "${major}" -eq 119 ]]; then
        is_vulnerable=true
    elif [[ "${major}" -eq 120 && "${minor}" -eq 0 && "${patch}" -lt 14 ]]; then
        is_vulnerable=true
    fi

    local fix_offered=false
    for cve in "${cves[@]}"; do
        local severity="${CVE_SEVERITY[$cve]}"
        local desc="${CVE_DESCRIPTIONS[$cve]}"

        if [[ "${is_vulnerable}" == true ]]; then
            print_result "FAIL" "${cve}" "${desc} — cPanel ${version} is vulnerable. Fix date: ${CVE_FIX_DATE[$cve]}" "${severity}"
            if [[ "${fix_offered}" == false && "${FLAG_FIX}" == true ]]; then
                fix_offered=true
                if fix_package "cpanel" "${cve}"; then
                    print_result "FIXED" "${cve}" "cPanel core updated." "${severity}"
                fi
            fi
        else
            print_result "PASS" "${cve}" "${desc} — cPanel ${version} is patched." "${severity}"
        fi
    done
}

# EasyApache4 v25.62
check_EASERVER_v25_62() {
    local cve="EASERVER-v25.62"
    local desc="${CVE_DESCRIPTIONS[$cve]}"
    local severity="${CVE_SEVERITY[$cve]}"
    local pkg="${CVE_PACKAGES[$cve]}"

    local installed_version
    installed_version=$(get_package_version "${pkg}")

    if [[ "${installed_version}" == "not-installed" ]]; then
        print_result "SKIP" "${cve}" "${desc} — EasyApache4 not installed." "${severity}"
        return
    fi

    # Check if update is available
    local available
    available=$(yum check-update "${pkg}" 2>/dev/null | grep "^${pkg}" | awk '{print $2}' || echo "")

    if [[ -n "${available}" ]]; then
        print_result "WARN" "${cve}" "${desc} — Update available: ${available}. Current: ${installed_version}" "${severity}"
        if fix_package "${pkg}" "${cve}"; then
            print_result "FIXED" "${cve}" "EasyApache4 updated." "${severity}"
        fi
    else
        print_result "PASS" "${cve}" "${desc} — EasyApache4 is up to date: ${installed_version}" "${severity}"
    fi
}

# LiteSpeed Auto-Remove Check
check_LITESPEED_AUTO_REMOVE() {
    local cve="LITESPEED-AUTO-REMOVE"
    local desc="${CVE_DESCRIPTIONS[$cve]}"
    local severity="${CVE_SEVERITY[$cve]}"

    local lsws_installed=false
    if rpm -q ea-lsws &>/dev/null || rpm -q lsws &>/dev/null; then
        lsws_installed=true
    fi

    if [[ "${lsws_installed}" == true ]]; then
        local lsws_version
        lsws_version=$(get_package_version "ea-lsws")
        print_result "WARN" "${cve}" \
            "${desc} — LiteSpeed is installed (${lsws_version}). Nightly update may auto-remove it. Verify your nightly update config." \
            "${severity}"
        log_to_file "WARN" "${cve}: LiteSpeed installed, auto-removal risk during nightly update"
    else
        print_result "PASS" "${cve}" "${desc} — LiteSpeed not installed. No risk." "${severity}"
    fi
}

# ---------------------------------------------------------------------------
# System Info
# ---------------------------------------------------------------------------
print_system_info() {
    print_section "System Information"
    local cpanel_ver
    cpanel_ver=$(get_cpanel_version)
    local hostname_val
    hostname_val=$(hostname -f 2>/dev/null || hostname)
    local os_rel
    os_rel=$(cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo "Unknown")
    local kernel_ver
    kernel_ver=$(uname -r)
    local uptime_val
    uptime_val=$(uptime -p 2>/dev/null || uptime)

    echo -e "  ${GRAY}Hostname    :${RESET}  ${WHITE}${hostname_val}${RESET}"
    echo -e "  ${GRAY}OS          :${RESET}  ${WHITE}${os_rel}${RESET}"
    echo -e "  ${GRAY}Kernel      :${RESET}  ${WHITE}${kernel_ver}${RESET}"
    echo -e "  ${GRAY}cPanel Ver  :${RESET}  ${WHITE}${cpanel_ver}${RESET}"
    echo -e "  ${GRAY}Uptime      :${RESET}  ${WHITE}${uptime_val}${RESET}"
    echo -e "  ${GRAY}Audit Time  :${RESET}  ${WHITE}$(date '+%Y-%m-%d %H:%M:%S %Z')${RESET}"
    echo -e "  ${GRAY}Log File    :${RESET}  ${WHITE}${LOG_FILE}${RESET}"
    [[ "${FLAG_REPORT}" == true ]] && \
        echo -e "  ${GRAY}HTML Report :${RESET}  ${WHITE}${HTML_FILE}${RESET}"

    log_to_file "INFO" "Host: ${hostname_val} | OS: ${os_rel} | Kernel: ${kernel_ver} | cPanel: ${cpanel_ver}"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    print_section "Audit Summary"

    local total_label="${WHITE}${TOTAL_CHECKS}${RESET}"
    local pass_label="${GREEN}${PASSED}${RESET}"
    local fail_label
    local warn_label="${YELLOW}${WARNED}${RESET}"
    local fixed_label="${CYAN}${FIXED}${RESET}"

    if [[ "${FAILED}" -gt 0 ]]; then
        fail_label="${RED}${BOLD}${FAILED}${RESET}"
    else
        fail_label="${GREEN}${FAILED}${RESET}"
    fi

    echo -e "  Total Checks : ${total_label}"
    echo -e "  ${GREEN}✔ Passed     :${RESET} ${pass_label}"
    echo -e "  ${RED}✘ Failed     :${RESET} ${fail_label}"
    echo -e "  ${YELLOW}⚠ Warnings   :${RESET} ${warn_label}"
    echo -e "  ${CYAN}↺ Fixed      :${RESET} ${fixed_label}"
    echo ""

    if [[ "${FAILED}" -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}⚠  This server has ${FAILED} unpatched vulnerabilities.${RESET}"
        echo -e "  ${DIM}Run with --fix to apply targeted package updates.${RESET}"
    elif [[ "${WARNED}" -gt 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}⚠  Audit passed with ${WARNED} warnings. Review above.${RESET}"
    else
        echo -e "  ${GREEN}${BOLD}✔  All checks passed. Server is up to date.${RESET}"
    fi

    echo ""
    echo -e "  ${DIM}Full log: ${LOG_FILE}${RESET}"

    log_to_file "SUMMARY" "Total=${TOTAL_CHECKS} Pass=${PASSED} Fail=${FAILED} Warn=${WARNED} Fixed=${FIXED}"
}

# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------
generate_html_report() {
    [[ "${FLAG_REPORT}" == false ]] && return

    local hostname_val
    hostname_val=$(hostname -f 2>/dev/null || hostname)
    local cpanel_ver
    cpanel_ver=$(get_cpanel_version)

    cat > "${HTML_FILE}" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cPanel Patch Radar — Audit Report</title>
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #58a6ff; --cyan: #39d353; --magenta: #bc8cff;
    --critical: #ff4444; --high: #ff8800; --medium: #ccaa00; --info: #58a6ff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }
  .header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 32px 40px; }
  .header h1 { font-size: 22px; font-weight: 600; color: var(--blue); margin-bottom: 4px; }
  .header .subtitle { color: var(--muted); font-size: 13px; }
  .container { max-width: 960px; margin: 0 auto; padding: 32px 40px; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 32px; }
  .meta-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .meta-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 4px; }
  .meta-card .value { font-size: 15px; font-weight: 600; color: var(--text); }
  .summary-bar { display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }
  .stat { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px 24px; flex: 1; min-width: 100px; text-align: center; }
  .stat .num { font-size: 28px; font-weight: 700; }
  .stat .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.8px; margin-top: 2px; }
  .stat.pass .num { color: var(--green); }
  .stat.fail .num { color: var(--red); }
  .stat.warn .num { color: var(--yellow); }
  .stat.fixed .num { color: var(--cyan); }
  .stat.total .num { color: var(--blue); }
  h2 { font-size: 16px; font-weight: 600; color: var(--text); margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; margin-bottom: 32px; }
  th { background: var(--bg3); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  td { padding: 12px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--bg3); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; }
  .badge-CRITICAL { background: rgba(255,68,68,0.15); color: var(--critical); border: 1px solid rgba(255,68,68,0.3); }
  .badge-HIGH { background: rgba(255,136,0,0.15); color: var(--high); border: 1px solid rgba(255,136,0,0.3); }
  .badge-MEDIUM { background: rgba(204,170,0,0.15); color: var(--medium); border: 1px solid rgba(204,170,0,0.3); }
  .badge-INFO { background: rgba(88,166,255,0.15); color: var(--info); border: 1px solid rgba(88,166,255,0.3); }
  .status-PASS { color: var(--green); font-weight: 600; }
  .status-FAIL { color: var(--red); font-weight: 600; }
  .status-WARN { color: var(--yellow); font-weight: 600; }
  .status-FIXED { color: var(--cyan); font-weight: 600; }
  .status-SKIP { color: var(--muted); }
  .footer { text-align: center; color: var(--muted); font-size: 12px; padding: 24px; border-top: 1px solid var(--border); margin-top: 32px; }
  .alert { padding: 14px 18px; border-radius: 8px; margin-bottom: 24px; font-size: 13px; }
  .alert-danger { background: rgba(248,81,73,0.1); border: 1px solid rgba(248,81,73,0.3); color: #f85149; }
  .alert-success { background: rgba(63,185,80,0.1); border: 1px solid rgba(63,185,80,0.3); color: #3fb950; }
  .alert-warning { background: rgba(210,153,34,0.1); border: 1px solid rgba(210,153,34,0.3); color: #d29922; }
</style>
</head>
<body>
<div class="header">
  <h1>🛡 cPanel Patch Radar — Security Audit Report</h1>
  <div class="subtitle">Generated on $(date '+%Y-%m-%d %H:%M:%S %Z') &nbsp;|&nbsp; Tool v${VERSION} &nbsp;|&nbsp; by Danial Sobhani</div>
</div>
<div class="container">
  <div class="meta-grid">
    <div class="meta-card"><div class="label">Hostname</div><div class="value">${hostname_val}</div></div>
    <div class="meta-card"><div class="label">cPanel Version</div><div class="value">${cpanel_ver}</div></div>
    <div class="meta-card"><div class="label">OS</div><div class="value">$(cat /etc/redhat-release 2>/dev/null | head -1 || echo "Linux")</div></div>
    <div class="meta-card"><div class="label">Kernel</div><div class="value">$(uname -r)</div></div>
  </div>

  <div class="summary-bar">
    <div class="stat total"><div class="num">${TOTAL_CHECKS}</div><div class="lbl">Total</div></div>
    <div class="stat pass"><div class="num">${PASSED}</div><div class="lbl">Passed</div></div>
    <div class="stat fail"><div class="num">${FAILED}</div><div class="lbl">Failed</div></div>
    <div class="stat warn"><div class="num">${WARNED}</div><div class="lbl">Warnings</div></div>
    <div class="stat fixed"><div class="num">${FIXED}</div><div class="lbl">Fixed</div></div>
  </div>

HTMLEOF

    if [[ "${FAILED}" -gt 0 ]]; then
        echo '  <div class="alert alert-danger">⚠ This server has <strong>'"${FAILED}"' unpatched vulnerabilities</strong>. Immediate action required.</div>' >> "${HTML_FILE}"
    elif [[ "${WARNED}" -gt 0 ]]; then
        echo '  <div class="alert alert-warning">⚠ Audit passed with '"${WARNED}"' warnings. Review recommended.</div>' >> "${HTML_FILE}"
    else
        echo '  <div class="alert alert-success">✔ All checks passed. Server is fully patched.</div>' >> "${HTML_FILE}"
    fi

    cat >> "${HTML_FILE}" << HTMLEOF2
  <h2>CVE Audit Results</h2>
  <table>
    <thead>
      <tr>
        <th>CVE / Advisory</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Description</th>
        <th>Fix Date</th>
      </tr>
    </thead>
    <tbody>
HTMLEOF2

    # Parse log for results
    while IFS= read -r line; do
        local status cve_id rest
        if echo "${line}" | grep -qE '\[(PASS|FAIL|WARN|FIXED|SKIP)\]'; then
            status=$(echo "${line}" | grep -oE '\[(PASS|FAIL|WARN|FIXED|SKIP)\]' | tr -d '[]')
            cve_id=$(echo "${line}" | sed 's/.*\] //' | cut -d: -f1)
            rest=$(echo "${line}" | sed 's/.*\] //' | cut -d: -f2-)

            local sev="${CVE_SEVERITY[$cve_id]:-INFO}"
            local fix_date="${CVE_FIX_DATE[$cve_id]:--}"

            echo "      <tr>" >> "${HTML_FILE}"
            echo "        <td><code>${cve_id}</code></td>" >> "${HTML_FILE}"
            echo "        <td><span class=\"badge badge-${sev}\">${sev}</span></td>" >> "${HTML_FILE}"
            echo "        <td><span class=\"status-${status}\">${status}</span></td>" >> "${HTML_FILE}"
            echo "        <td>${rest}</td>" >> "${HTML_FILE}"
            echo "        <td>${fix_date}</td>" >> "${HTML_FILE}"
            echo "      </tr>" >> "${HTML_FILE}"
        fi
    done < "${LOG_FILE}"

    cat >> "${HTML_FILE}" << HTMLEOF3
    </tbody>
  </table>
</div>
<div class="footer">
  cpanel-patch-radar v${VERSION} &nbsp;|&nbsp; <a href="https://github.com/danialsobhani/cpanel-patch-radar" style="color:#58a6ff">github.com/danialsobhani/cpanel-patch-radar</a>
</div>
</body>
</html>
HTMLEOF3

    print_info "HTML report saved: ${HTML_FILE}"
    log_to_file "INFO" "HTML report generated: ${HTML_FILE}"
}

# ---------------------------------------------------------------------------
# Run All Checks
# ---------------------------------------------------------------------------
run_all_checks() {
    print_section "CVE Audit — cPanel/WHM"

    if [[ -n "${FLAG_SPECIFIC_CVE}" ]]; then
        local fn_name="check_${FLAG_SPECIFIC_CVE//-/_}"
        fn_name="${fn_name//./_}"
        if declare -f "${fn_name}" > /dev/null 2>&1; then
            "${fn_name}"
        else
            print_warn "No check function found for: ${FLAG_SPECIFIC_CVE}"
            print_info "Available CVEs: CVE-2026-41940, CVE-2026-9256, CVE-2026-33278"
        fi
        return
    fi

    check_CVE_2026_41940
    check_CVE_2026_9256
    check_CVE_2026_33278
    check_cpanel_core_cves
    check_EASERVER_v25_62
    check_LITESPEED_AUTO_REMOVE
}



# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fix)      FLAG_FIX=true ;;
            --report)   FLAG_REPORT=true ;;
            --backup)   FLAG_BACKUP=true ;;
            --quiet)    FLAG_QUIET=true ;;
            --cve)
                shift
                FLAG_SPECIFIC_CVE="${1:-}"
                ;;
            --version)
                echo "${TOOL_NAME} v${VERSION}"
                exit 0
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    [[ "${FLAG_QUIET}" == false ]] && print_banner

    check_root
    check_cpanel
    setup_log_dir

    log_to_file "START" "cpanel-patch-radar v${VERSION} started. Flags: fix=${FLAG_FIX} report=${FLAG_REPORT} backup=${FLAG_BACKUP}"

    print_system_info
    run_all_checks
    generate_html_report
    print_summary
}

main "$@"
