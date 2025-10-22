# Docker Deployment Automation Script

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A production-grade Bash script that automates the setup, deployment, and configuration of Dockerized applications on remote Linux servers, with a focus on AWS EC2 instances.

## Features

- **Complete Deployment Pipeline**: Handles every aspect of deployment from git clone to Nginx configuration
- **Robust Error Handling**: Comprehensive validation and error recovery mechanisms
- **Detailed Logging**: Full audit trail of all operations with timestamps
- **AWS EC2 Optimized**: Special handling for common EC2 connection issues
- **Idempotent Execution**: Safe to run multiple times without breaking existing setups
- **Cleanup Mode**: Optional flag to remove all deployed resources
- **Custom SSH Port**: Support for non-standard SSH ports

## Requirements

- Bash shell environment
- Git
- SSH client
- rsync
- Docker and Docker Compose (on the remote server)

## Usage

### Basic Deployment

```bash
# Make the script executable
chmod +x deploy.sh

# Run the deployment
./deploy.sh
```

### Custom SSH Port

```bash
# Using non-standard SSH port (e.g., 2222)
./deploy.sh --port 2222
```

### Cleanup Resources

```bash
# Remove all deployed resources
./deploy.sh --cleanup
```

### Get Help

```bash
./deploy.sh --help
```

## Parameter Details

The script will interactively prompt for the following parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| Git Repository URL | URL of the git repository to deploy | `https://github.com/username/repo.git` |
| Personal Access Token (PAT) | Authentication token for Git repository | `ghp_xxxxxxxxxxxxxxxxxxxx` |
| Branch Name | Git branch to deploy (defaults to main) | `main` |
| SSH Username | Username for SSH login to remote server | `ubuntu` |
| Server IP | IP address of the remote server | `12.34.56.78` |
| SSH Key Path | Path to the SSH private key | `~/.ssh/id_rsa` |
| Application Port | Internal port the application uses | `3000` |
| SSH Port (optional) | Custom SSH port if not using default 22 | `2222` |

## Workflow

1. **Parameter Collection**: Validates all required inputs
2. **Git Operations**: Clones or updates the repository
3. **SSH Connection**: Tests and diagnoses connectivity to the remote server
4. **Environment Preparation**: Installs Docker, Docker Compose, and Nginx
5. **Application Deployment**: Transfers files and builds/runs containers
6. **Nginx Configuration**: Sets up reverse proxy to the application
7. **Validation**: Confirms all components are working correctly

## AWS EC2 Specific Features

- Automatically detects common EC2 SSH issues
- Suggests correct usernames based on AMI type
- Provides security group troubleshooting guidance
- Handles key permission requirements
- Supports custom SSH ports for enhanced security

## Logging

The script creates a detailed log file with timestamp in the format:
```
deploy_YYYYMMDD_HHMMSS.log
```

Each log entry includes:
- Timestamp
- Log level (INFO, SUCCESS, WARN, ERROR)
- Detailed message

## Troubleshooting

If you encounter SSH connection issues:

1. **Check Security Group**: Ensure port 22 (or your custom SSH port) is open
2. **Verify Instance Status**: Confirm your EC2 instance is running
3. **Key Permissions**: Ensure your SSH key has correct permissions (chmod 400)
4. **AMI Username**: Use the correct username for your AMI:
   - Amazon Linux: `ec2-user`
   - Ubuntu: `ubuntu`
   - Debian: `admin`
   - RHEL: `ec2-user` or `root`
5. **Run Verbose SSH**: `ssh -vvv -i your_key.pem user@ip`

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Invalid input parameters |
| 2 | Git operation failed |
| 3 | SSH connection failed |
| 4 | Docker operation failed |
| 5 | Nginx configuration failed |
| 6 | Validation error |
| 130 | Script interrupted by user |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

baydre_africa | HNGi13 DevOps Team