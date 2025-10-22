A step-by-step guide and explanation of how to approach the task, **without writing the actual code**, focusing on the logic and required actions.

---

## 🎯 Task Objective Overview

The main goal is to create a single, robust, and reliable **Bash script** (`deploy.sh`) that acts as a fully automated deployment pipeline. This script will take a Dockerized application from a Git repository and deploy it to a remote Linux server, setting up the necessary runtime environment (Docker, Docker Compose) and a reverse proxy (Nginx) for web accessibility.

---

## 💡 Conceptual Breakdown

### **1. Automation via Bash**
* **Why Bash?** It's the standard shell for Linux/Unix environments, making it ideal for scripting system administration and deployment tasks without external tools like Ansible.
* **Key Concept:** The script uses built-in shell commands (`read`, `if/else`, `ssh`, `scp`, `git`, `docker`, `nginx`) and logical flow control to execute a long series of steps in a predefined, repeatable order.

### **2. Security & Credentials**
* **PAT:** A **Personal Access Token** is used instead of a password for Git authentication, offering better security and granular control over repository access.
* **SSH Key:** Using an **SSH key** is the standard, secure way to access the remote server without providing a password interactively.

### **3. Remote Execution**
* **SSH Tunneling:** The script leverages the `ssh` command to execute multiple commands **remotely**. It doesn't need to stay connected after the initial login; it can pass an entire block of commands to be run on the server.
* **File Transfer:** Commands like `scp` (Secure Copy) or `rsync` are used to securely copy the application source code from the local machine to the remote server.

### **4. Idempotency**
* **Definition:** A script is **idempotent** if running it multiple times produces the same result as running it once.
* **Why it Matters:** In this context, it means the script must handle existing installations. For example, it must check if Docker is already installed before attempting to install it again, or stop/remove an existing container before deploying a new one.

---

## 📝 Step-by-Step Implementation Guide

### **Phase 1: Local Setup & Parameter Collection**

| Step | Action Required | Key Commands/Concept |
| :--- | :--- | :--- |
| **1.1 Input & Validation** | Prompt the user for all necessary details (Git URL, PAT, SSH details, etc.). | `read -p`, `if/then` checks for non-empty/valid inputs, **parameter expansion** for optional defaults (e.g., `${BRANCH:-main}`). |
| **1.2 Logging Initialization** | Set up the log file with a timestamp and start capturing all script output. | `LOG_FILE=deploy_$(date +%Y%m%d_%H%M%S).log`, use **redirection** (`exec 1> >(tee -a $LOG_FILE) 2>&1`) to capture all output and errors. |
| **1.3 Error Trapping** | Define a function to catch non-zero exit codes (errors) and immediately log and exit the script. | `trap 'error_handler $LINENO' ERR` |

### **Phase 2: Local Git Operations**

| Step | Action Required | Key Commands/Concept |
| :--- | :--- | :--- |
| **2.1 Clone/Pull** | Check if the project directory exists. If yes, run `git pull`. If no, run `git clone` using the PAT for authentication. | **Credential format:** `https://${PAT}@github.com/user/repo.git`. **Conditional execution** (`if [ -d $DIR ]; then...`). |
| **2.2 Branch Switch** | Navigate into the project directory and switch to the specified branch. | `cd $DIR`, `git checkout $BRANCH` |
| **2.3 Artifact Check** | Verify that a deployment file (`Dockerfile` or `docker-compose.yml`) exists in the directory. | `if [ -f Dockerfile ]` or `[ -f docker-compose.yml ]` conditional check |

### **Phase 3: Remote Environment Preparation**

| Step | Action Required | Key Commands/Concept |
| :--- | :--- | :--- |
| **3.1 Connectivity Check** | Verify that the local machine can connect to the remote server via SSH. | `ssh -i $KEY -o BatchMode=yes -o ConnectTimeout=5 $USER@$IP "exit"` |
| **3.2 Server Setup (Remote)** | Execute a block of commands remotely to prepare the server. **This is one critical `ssh` call.** | `ssh -i $KEY $USER@$IP "sudo apt update -y; install_docker_nginx; start_services;"` (The `install_docker_nginx` would be a function/script executed inside the quotes). |
| **3.3 Docker/Nginx Install** | Check if Docker/Docker Compose/Nginx are installed. Install them only if missing. Add the deploy user to the `docker` group. | `dpkg -l \| grep docker`, `curl ... \| sh` (for Docker install), `sudo usermod -aG docker $USER`. |

### **Phase 4: Deployment & Validation**

| Step | Action Required | Key Commands/Concept |
| :--- | :--- | :--- |
| **4.1 File Transfer** | Copy the *entire* local project folder to a target location (e.g., `/home/$USER/app_name`) on the remote server. | `scp -r -i $KEY ./$DIR $USER@$IP:/path/` |
| **4.2 Stop Old Containers (Remote)** | Before deploying, stop and remove any existing container/service associated with this application to ensure a clean slate (idempotency). | `docker stop $CONTAINER_NAME; docker rm $CONTAINER_NAME` or `docker-compose down`. |
| **4.3 Build and Run (Remote)** | Navigate to the transferred directory remotely and deploy the application. | `cd /path/app_name && docker-compose up -d --build` (or equivalent `docker build/run`). |
| **4.4 Application Health Check (Remote)** | Confirm the container is running and healthy. | `docker ps -f name=$CONTAINER_NAME -f status=running`, `docker logs $CONTAINER_NAME` |

### **Phase 5: Nginx Reverse Proxy Configuration**

| Step | Action Required | Key Commands/Concept |
| :--- | :--- | :--- |
| **5.1 Config Creation (Remote)** | Dynamically create the Nginx configuration file, substituting the correct **Application Port** captured in Step 1.1. | Use **'here-documents'** (`cat <<EOF > /etc/nginx/sites-available/app`) inside the remote `ssh` command to write a multi-line config file. |
| **5.2 Enable & Test (Remote)** | Create a symlink to enable the config, test the Nginx configuration syntax, and reload the service. | `sudo ln -sf /path/to/config /etc/nginx/sites-enabled/`, `sudo nginx -t`, `sudo systemctl reload nginx`. |

### **Phase 6: Final Validation & Idempotency**

| Step | Action Required | Key Commands/Concept |
| :--- | :--- | :--- |
| **6.1 Deployment Check (Remote)** | Use `curl` on the remote server to test the **public port 80** to confirm Nginx is correctly forwarding to the container. | `curl -sL http://localhost/` |
| **6.2 Final Validation (Local)** | Use `curl` on the local machine to test the public IP of the remote server. | `curl -sL http://$IP/` |
| **6.3 Optional Cleanup** | Implement an optional flag check (e.g., `if [ "$1" == "--cleanup" ]; then...`) to remove all created resources (Nginx config, containers, project directory) and exit. | Requires **conditional execution** and a defined cleanup function. |
| **6.4 Final Log/Exit** | Log the final success or failure message and exit with the appropriate exit code (`0` for success). | `exit 0` |