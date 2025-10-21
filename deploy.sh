#!/usr/bin/env bash

#############################################################################
# Production-Grade Docker Deployment Script
# Description: Automates setup, deployment, and configuration of Dockerized
#              applications on remote Linux servers
# Author: DevOps Team
# Version: 1.0.0
#############################################################################

set -o pipefail
set -o nounset

#############################################################################
# GLOBAL VARIABLES
#############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/deploy_$(date +%Y%m%d_%H%M%S).log"
TEMP_DIR="${SCRIPT_DIR}/.tmp_deploy_$$"
REPO_DIR=""
CONTAINER_NAME="app_container_${RANDOM}"
NGINX_SITE_NAME="dockerapp"
CLEANUP_MODE=false

# Exit codes
readonly EXIT_SUCCESS=0
readonly EXIT_INVALID_INPUT=1
readonly EXIT_GIT_ERROR=2
readonly EXIT_SSH_ERROR=3
readonly EXIT_DOCKER_ERROR=4
readonly EXIT_NGINX_ERROR=5
readonly EXIT_VALIDATION_ERROR=6

#############################################################################
# LOGGING FUNCTIONS
#############################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

log_info() {
    log "INFO" "$@"
}

log_success() {
    log "SUCCESS" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_warn() {
    log "WARN" "$@"
}

#############################################################################
# ERROR HANDLING
#############################################################################

cleanup_on_exit() {
    local exit_code=$?
    if [ -d "${TEMP_DIR}" ]; then
        rm -rf "${TEMP_DIR}"
        log_info "Cleaned up temporary directory"
    fi
    if [ ${exit_code} -ne 0 ]; then
        log_error "Script exited with error code: ${exit_code}"
    fi
}

trap cleanup_on_exit EXIT
trap 'log_error "Script interrupted by user"; exit 130' INT TERM

error_exit() {
    local message="$1"
    local exit_code="${2:-1}"
    log_error "${message}"
    exit "${exit_code}"
}

#############################################################################
# VALIDATION FUNCTIONS
#############################################################################

validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
}

validate_ssh_key() {
    local key_path="$1"
    if [ -f "$key_path" ] && [ -r "$key_path" ]; then
        return 0
    fi
    return 1
}

#############################################################################
# INPUT COLLECTION
#############################################################################

collect_user_input() {
    log_info "=== Starting Parameter Collection ==="
    
    # Git Repository URL
    while true; do
        read -p "Enter Git Repository URL: " GIT_REPO_URL
        if validate_url "$GIT_REPO_URL"; then
            log_info "Repository URL validated: ${GIT_REPO_URL}"
            break
        else
            log_error "Invalid URL format. Please try again."
        fi
    done
    
    # Personal Access Token
    while true; do
        read -sp "Enter Personal Access Token (PAT): " GIT_PAT
        echo
        if [ -n "$GIT_PAT" ]; then
            log_info "PAT received (hidden)"
            break
        else
            log_error "PAT cannot be empty"
        fi
    done
    
    # Branch name
    read -p "Enter branch name [default: main]: " GIT_BRANCH
    GIT_BRANCH=${GIT_BRANCH:-main}
    log_info "Branch set to: ${GIT_BRANCH}"
    
    # SSH Username
    read -p "Enter remote server username: " SSH_USER
    log_info "SSH user: ${SSH_USER}"
    
    # Server IP
    while true; do
        read -p "Enter remote server IP address: " SERVER_IP
        if validate_ip "$SERVER_IP"; then
            log_info "Server IP validated: ${SERVER_IP}"
            break
        else
            log_error "Invalid IP address format"
        fi
    done
    
    # SSH Key Path
    while true; do
        read -p "Enter SSH private key path: " SSH_KEY_PATH
        SSH_KEY_PATH="${SSH_KEY_PATH/#\~/$HOME}"
        if validate_ssh_key "$SSH_KEY_PATH"; then
            log_info "SSH key validated: ${SSH_KEY_PATH}"
            break
        else
            log_error "SSH key not found or not readable"
        fi
    done
    
    # Application Port
    while true; do
        read -p "Enter application internal port: " APP_PORT
        if validate_port "$APP_PORT"; then
            log_info "Application port set to: ${APP_PORT}"
            break
        else
            log_error "Invalid port number (1-65535)"
        fi
    done
    
    log_success "All parameters collected successfully"
}

#############################################################################
# GIT OPERATIONS
#############################################################################

clone_repository() {
    log_info "=== Starting Repository Clone ==="
    
    local repo_name=$(basename "$GIT_REPO_URL" .git)
    REPO_DIR="${TEMP_DIR}/${repo_name}"
    
    mkdir -p "${TEMP_DIR}"
    
    # Build authenticated URL
    local auth_url=$(echo "$GIT_REPO_URL" | sed "s|https://|https://${GIT_PAT}@|")
    
    if [ -d "$REPO_DIR" ]; then
        log_warn "Repository directory exists, pulling latest changes..."
        cd "$REPO_DIR" || error_exit "Cannot access repository directory" ${EXIT_GIT_ERROR}
        
        git fetch origin "${GIT_BRANCH}" >> "${LOG_FILE}" 2>&1 || \
            error_exit "Failed to fetch from repository" ${EXIT_GIT_ERROR}
        
        git checkout "${GIT_BRANCH}" >> "${LOG_FILE}" 2>&1 || \
            error_exit "Failed to checkout branch ${GIT_BRANCH}" ${EXIT_GIT_ERROR}
        
        git pull origin "${GIT_BRANCH}" >> "${LOG_FILE}" 2>&1 || \
            error_exit "Failed to pull latest changes" ${EXIT_GIT_ERROR}
    else
        log_info "Cloning repository..."
        git clone -b "${GIT_BRANCH}" "${auth_url}" "${REPO_DIR}" >> "${LOG_FILE}" 2>&1 || \
            error_exit "Failed to clone repository" ${EXIT_GIT_ERROR}
        
        cd "$REPO_DIR" || error_exit "Cannot access cloned directory" ${EXIT_GIT_ERROR}
    fi
    
    log_success "Repository ready at: ${REPO_DIR}"
}

verify_docker_files() {
    log_info "=== Verifying Docker Configuration Files ==="
    
    if [ -f "Dockerfile" ]; then
        log_success "Found Dockerfile"
        USE_COMPOSE=false
    elif [ -f "docker-compose.yml" ] || [ -f "docker-compose.yaml" ]; then
        log_success "Found docker-compose.yml"
        USE_COMPOSE=true
    else
        error_exit "No Dockerfile or docker-compose.yml found in repository" ${EXIT_VALIDATION_ERROR}
    fi
}

#############################################################################
# SSH OPERATIONS
#############################################################################

test_ssh_connection() {
    log_info "=== Testing SSH Connection ==="
    
    # Test ping
    if ping -c 1 -W 5 "${SERVER_IP}" > /dev/null 2>&1; then
        log_success "Server is reachable via ping"
    else
        log_warn "Server not responding to ping (might be blocked)"
    fi
    
    # Test SSH connection
    if ssh -i "${SSH_KEY_PATH}" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "${SSH_USER}@${SERVER_IP}" "echo 'SSH connection successful'" >> "${LOG_FILE}" 2>&1; then
        log_success "SSH connection established successfully"
    else
        error_exit "Failed to establish SSH connection" ${EXIT_SSH_ERROR}
    fi
}

execute_remote_command() {
    local command="$1"
    local error_message="${2:-Remote command failed}"
    
    ssh -i "${SSH_KEY_PATH}" -o StrictHostKeyChecking=no \
        "${SSH_USER}@${SERVER_IP}" "${command}" >> "${LOG_FILE}" 2>&1 || \
        error_exit "${error_message}" ${EXIT_SSH_ERROR}
}

#############################################################################
# REMOTE ENVIRONMENT SETUP
#############################################################################

prepare_remote_environment() {
    log_info "=== Preparing Remote Environment ==="
    
    log_info "Updating system packages..."
    execute_remote_command "sudo apt-get update -y" "Failed to update packages"
    
    log_info "Installing required packages..."
    execute_remote_command \
        "sudo apt-get install -y docker.io docker-compose nginx curl" \
        "Failed to install required packages"
    
    log_info "Adding user to docker group..."
    execute_remote_command "sudo usermod -aG docker ${SSH_USER}" || log_warn "User already in docker group"
    
    log_info "Enabling and starting services..."
    execute_remote_command "sudo systemctl enable docker" "Failed to enable Docker"
    execute_remote_command "sudo systemctl start docker" "Failed to start Docker"
    execute_remote_command "sudo systemctl enable nginx" "Failed to enable Nginx"
    execute_remote_command "sudo systemctl start nginx" "Failed to start Nginx"
    
    log_info "Verifying installations..."
    execute_remote_command "docker --version" "Docker not installed correctly"
    execute_remote_command "docker-compose --version" "Docker Compose not installed correctly"
    execute_remote_command "nginx -v" "Nginx not installed correctly"
    
    log_success "Remote environment prepared successfully"
}

#############################################################################
# APPLICATION DEPLOYMENT
#############################################################################

transfer_files() {
    log_info "=== Transferring Application Files ==="
    
    local remote_dir="/home/${SSH_USER}/app_deploy_$(date +%s)"
    
    log_info "Creating remote directory: ${remote_dir}"
    execute_remote_command "mkdir -p ${remote_dir}" "Failed to create remote directory"
    
    log_info "Transferring files via rsync..."
    rsync -avz --progress -e "ssh -i ${SSH_KEY_PATH} -o StrictHostKeyChecking=no" \
        "${REPO_DIR}/" "${SSH_USER}@${SERVER_IP}:${remote_dir}/" >> "${LOG_FILE}" 2>&1 || \
        error_exit "Failed to transfer files" ${EXIT_SSH_ERROR}
    
    REMOTE_APP_DIR="${remote_dir}"
    log_success "Files transferred to: ${REMOTE_APP_DIR}"
}

deploy_docker_application() {
    log_info "=== Deploying Docker Application ==="
    
    # Stop and remove existing containers with same name
    log_info "Cleaning up existing containers..."
    execute_remote_command \
        "docker stop ${CONTAINER_NAME} 2>/dev/null || true" \
        || log_warn "No existing container to stop"
    
    execute_remote_command \
        "docker rm ${CONTAINER_NAME} 2>/dev/null || true" \
        || log_warn "No existing container to remove"
    
    if [ "$USE_COMPOSE" = true ]; then
        log_info "Deploying with docker-compose..."
        execute_remote_command \
            "cd ${REMOTE_APP_DIR} && docker-compose down 2>/dev/null || true" \
            || log_warn "No existing compose deployment"
        
        execute_remote_command \
            "cd ${REMOTE_APP_DIR} && docker-compose up -d --build" \
            "Docker Compose deployment failed"
        
        CONTAINER_NAME=$(ssh -i "${SSH_KEY_PATH}" -o StrictHostKeyChecking=no \
            "${SSH_USER}@${SERVER_IP}" \
            "cd ${REMOTE_APP_DIR} && docker-compose ps -q | head -n1 | xargs docker inspect --format='{{.Name}}' | sed 's/\///'" 2>/dev/null || echo "compose_app")
    else
        log_info "Building Docker image..."
        execute_remote_command \
            "cd ${REMOTE_APP_DIR} && docker build -t app_image:latest ." \
            "Docker build failed"
        
        log_info "Running Docker container..."
        execute_remote_command \
            "docker run -d --name ${CONTAINER_NAME} -p ${APP_PORT}:${APP_PORT} app_image:latest" \
            "Docker run failed"
    fi
    
    log_info "Waiting for container to start..."
    sleep 5
    
    log_info "Checking container status..."
    execute_remote_command \
        "docker ps | grep ${CONTAINER_NAME}" \
        "Container is not running"
    
    log_success "Docker application deployed successfully"
}

#############################################################################
# NGINX CONFIGURATION
#############################################################################

configure_nginx() {
    log_info "=== Configuring Nginx Reverse Proxy ==="
    
    local nginx_config="/etc/nginx/sites-available/${NGINX_SITE_NAME}"
    local nginx_enabled="/etc/nginx/sites-enabled/${NGINX_SITE_NAME}"
    
    log_info "Creating Nginx configuration..."
    
    cat > "${TEMP_DIR}/nginx_config" << EOF
server {
    listen 80;
    server_name ${SERVER_IP};

    location / {
        proxy_pass http://localhost:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    
    log_info "Uploading Nginx configuration..."
    scp -i "${SSH_KEY_PATH}" -o StrictHostKeyChecking=no \
        "${TEMP_DIR}/nginx_config" \
        "${SSH_USER}@${SERVER_IP}:/tmp/nginx_config" >> "${LOG_FILE}" 2>&1 || \
        error_exit "Failed to upload Nginx config" ${EXIT_NGINX_ERROR}
    
    execute_remote_command \
        "sudo mv /tmp/nginx_config ${nginx_config}" \
        "Failed to move Nginx config"
    
    execute_remote_command \
        "sudo ln -sf ${nginx_config} ${nginx_enabled}" \
        "Failed to enable Nginx site"
    
    log_info "Testing Nginx configuration..."
    execute_remote_command \
        "sudo nginx -t" \
        "Nginx configuration test failed"
    
    log_info "Reloading Nginx..."
    execute_remote_command \
        "sudo systemctl reload nginx" \
        "Failed to reload Nginx"
    
    log_success "Nginx configured successfully"
}

#############################################################################
# VALIDATION
#############################################################################

validate_deployment() {
    log_info "=== Validating Deployment ==="
    
    log_info "Checking Docker service..."
    execute_remote_command \
        "sudo systemctl is-active docker" \
        "Docker service is not running"
    
    log_info "Checking container health..."
    execute_remote_command \
        "docker ps | grep ${CONTAINER_NAME}" \
        "Container is not running"
    
    log_info "Checking Nginx service..."
    execute_remote_command \
        "sudo systemctl is-active nginx" \
        "Nginx service is not running"
    
    log_info "Testing application endpoint (port ${APP_PORT})..."
    execute_remote_command \
        "curl -f http://localhost:${APP_PORT} > /dev/null 2>&1" \
        || log_warn "Direct container access failed (might be normal if app needs setup)"
    
    log_info "Testing Nginx proxy (port 80)..."
    execute_remote_command \
        "curl -f http://localhost > /dev/null 2>&1" \
        || log_warn "Nginx proxy test failed (app might need additional setup)"
    
    log_info "Testing external access..."
    if curl -f "http://${SERVER_IP}" > /dev/null 2>&1; then
        log_success "External access validated successfully"
    else
        log_warn "External access test failed (check firewall rules)"
    fi
    
    log_success "Deployment validation completed"
}

#############################################################################
# CLEANUP FUNCTION
#############################################################################

cleanup_deployment() {
    log_info "=== Cleaning Up Deployment ==="
    
    log_info "Stopping and removing containers..."
    execute_remote_command \
        "docker stop ${CONTAINER_NAME} 2>/dev/null || true" \
        || log_warn "No container to stop"
    
    execute_remote_command \
        "docker rm ${CONTAINER_NAME} 2>/dev/null || true" \
        || log_warn "No container to remove"
    
    if [ "$USE_COMPOSE" = true ]; then
        execute_remote_command \
            "cd ${REMOTE_APP_DIR} && docker-compose down 2>/dev/null || true" \
            || log_warn "No compose deployment to remove"
    fi
    
    log_info "Removing Nginx configuration..."
    execute_remote_command \
        "sudo rm -f /etc/nginx/sites-enabled/${NGINX_SITE_NAME}" \
        || log_warn "No Nginx config to remove"
    
    execute_remote_command \
        "sudo rm -f /etc/nginx/sites-available/${NGINX_SITE_NAME}" \
        || log_warn "No Nginx config to remove"
    
    execute_remote_command \
        "sudo systemctl reload nginx" \
        || log_warn "Failed to reload Nginx"
    
    log_info "Removing application files..."
    execute_remote_command \
        "rm -rf ${REMOTE_APP_DIR}" \
        || log_warn "Failed to remove application directory"
    
    log_success "Cleanup completed"
}

#############################################################################
# MAIN EXECUTION
#############################################################################

print_banner() {
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        Docker Deployment Automation Script v1.0.0            ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
}

print_summary() {
    log_info "=== Deployment Summary ==="
    log_info "Repository: ${GIT_REPO_URL}"
    log_info "Branch: ${GIT_BRANCH}"
    log_info "Remote Server: ${SSH_USER}@${SERVER_IP}"
    log_info "Application Port: ${APP_PORT}"
    log_info "Container Name: ${CONTAINER_NAME}"
    log_info "Access URL: http://${SERVER_IP}"
    log_info "Log File: ${LOG_FILE}"
    log_info "================================================"
}

main() {
    print_banner
    log_info "Deployment started at $(date)"
    
    # Check for cleanup flag
    if [ "${1:-}" = "--cleanup" ]; then
        CLEANUP_MODE=true
        log_info "Running in CLEANUP mode"
        collect_user_input
        test_ssh_connection
        cleanup_deployment
        log_success "Cleanup completed successfully"
        exit ${EXIT_SUCCESS}
    fi
    
    # Normal deployment flow
    collect_user_input
    clone_repository
    verify_docker_files
    test_ssh_connection
    prepare_remote_environment
    transfer_files
    deploy_docker_application
    configure_nginx
    validate_deployment
    
    print_summary
    log_success "Deployment completed successfully at $(date)"
    echo ""
    echo "🎉 Deployment successful! Access your application at: http://${SERVER_IP}"
    echo "📝 Full log available at: ${LOG_FILE}"
}

# Run main function
main "$@"