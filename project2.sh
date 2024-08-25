#!/bin/bash

# Function to list all users and groups
list_users_groups() {
    echo "Listing all users and groups..."
    cat /etc/passwd
    cat /etc/group
}

# Function to check for users with UID 0
check_uid_0_users() {
    echo "Checking for users with UID 0..."
    awk -F: '($3 == 0) {print}' /etc/passwd
}

# Function to identify users without passwords or with weak passwords
check_weak_passwords() {
    echo "Checking for users without passwords or with weak passwords..."
    awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow
}

# Function to scan for world-writable files and directories
scan_world_writable() {
    echo "Scanning for world-writable files and directories..."
    find / -perm -002 -type f -exec ls -l {} \;
    find / -perm -002 -type d -exec ls -ld {} \;
}

# Function to check .ssh directory permissions
check_ssh_permissions() {
    echo "Checking .ssh directory permissions..."
    find /home -type d -name ".ssh" -exec chmod 700 {} \;
    find /home -type f -name "authorized_keys" -exec chmod 600 {} \;
}

# Function to list all running services
list_running_services() {
    echo "Listing all running services..."
    systemctl list-units --type=service --state=running
}

# Function to check for unnecessary or unauthorized services
check_unnecessary_services() {
    echo "Checking for unnecessary or unauthorized services..."
    # Add your list of critical services here
    critical_services=("sshd" "iptables")
    for service in "${critical_services[@]}"; do
        systemctl is-active --quiet $service || echo "$service is not running"
    done
}

# Function to verify firewall status
verify_firewall() {
    echo "Verifying firewall status..."
    if command -v ufw &> /dev/null; then
        ufw status
    elif command -v iptables &> /dev/null; then
        iptables -L
    else
        echo "No firewall found"
    fi
}

# Function to check IP configuration
check_ip_config() {
    echo "Checking IP configuration..."
    ip -4 addr show
    ip -6 addr show
}

# Function to identify public vs. private IPs
identify_ip_type() {
    echo "Identifying public vs. private IPs..."
    ip -4 addr show | grep -Eo 'inet [0-9.]+/[0-9]+' | awk '{print $2}' | while read -r ip; do
        if [[ $ip =~ ^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\. ]]; then
            echo "Private IP: $ip"
        else
            echo "Public IP: $ip"
        fi
    done
}

# Function to check for security updates
check_security_updates() {
    echo "Checking for security updates..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get upgrade -s | grep -i security
    elif command -v yum &> /dev/null; then
        yum check-update --security
    else
        echo "Package manager not found"
    fi
}

# Function to check logs for suspicious activity
check_logs() {
    echo "Checking logs for suspicious activity..."
    grep -i "failed" /var/log/auth.log
    grep -i "error" /var/log/syslog
}

# Main function to run all checks
main() {
    list_users_groups
    check_uid_0_users
    check_weak_passwords
    scan_world_writable
    check_ssh_permissions
    list_running_services
    check_unnecessary_services
    verify_firewall
    check_ip_config
    identify_ip_type
    check_security_updates
    check_logs
}

# Run the main function
main
