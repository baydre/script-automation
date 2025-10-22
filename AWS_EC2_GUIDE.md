# AWS EC2 Quick Start Guide

This guide provides step-by-step instructions for setting up and using the deployment script with AWS EC2 instances.

## Step 1: Launch an EC2 Instance

### Using AWS Console:
1. Go to AWS Console → EC2 → Launch Instance
2. Choose Ubuntu Server 22.04 LTS or Amazon Linux 2
3. Select an instance type (t2.micro for free tier)
4. Configure security groups (see Step 2)
5. Create or select an existing key pair
6. Launch the instance

### Using AWS CLI:
```bash
aws ec2 run-instances \
  --image-id ami-0c7217cdde317cfec \
  --instance-type t2.micro \
  --key-name your-key-name \
  --security-group-ids sg-xxxxxxxxx \
  --subnet-id subnet-xxxxxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=DockerAppServer}]'
```

## Step 2: Configure Security Group

### Required Inbound Rules:
- SSH (port 22) - Your IP address or 0.0.0.0/0
- HTTP (port 80) - 0.0.0.0/0
- HTTPS (port 443) - 0.0.0.0/0 (if using SSL)
- Custom TCP (your app port) - Optional for direct access

### Using AWS Console:
1. Go to EC2 → Security Groups
2. Create a new security group or select existing one
3. Add the required inbound rules

### Using AWS CLI:
```bash
# Allow SSH
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 22 \
  --cidr YOUR_IP/32

# Allow HTTP
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxxxxxxxx \
  --protocol tcp \
  --port 80 \
  --cidr 0.0.0.0/0
```

## Step 3: Prepare SSH Key

1. Download your key pair (.pem file)
2. Move to a secure location:
```bash
mkdir -p ~/.ssh/aws-keys
mv ~/Downloads/my-key.pem ~/.ssh/aws-keys/
```

3. Set proper permissions:
```bash
chmod 400 ~/.ssh/aws-keys/my-key.pem
```

4. Test SSH connection:
```bash
# For Amazon Linux 2:
ssh -i ~/.ssh/aws-keys/my-key.pem ec2-user@YOUR_EC2_PUBLIC_IP

# For Ubuntu:
ssh -i ~/.ssh/aws-keys/my-key.pem ubuntu@YOUR_EC2_PUBLIC_IP
```

## Step 4: Prepare Your GitHub Repository

1. Ensure your repository has either:
   - A Dockerfile, OR
   - A docker-compose.yml file

2. Create a Personal Access Token (PAT):
   - Go to GitHub → Settings → Developer Settings → Personal Access Tokens → Tokens (classic)
   - Generate new token with 'repo' scope
   - Save it securely!

## Step 5: Run the Deployment Script

1. Make the script executable:
```bash
chmod +x deploy.sh
```

2. Run the deployment:
```bash
./deploy.sh
```

3. Enter the requested information:
   - Git Repository URL: `https://github.com/yourusername/your-repo.git`
   - PAT: Your GitHub Personal Access Token
   - Branch: `main` (or your branch name)
   - Remote server username: `ec2-user` for Amazon Linux, `ubuntu` for Ubuntu
   - Server IP: Your EC2 instance's public IP address
   - SSH key path: Path to your .pem file (e.g., `~/.ssh/aws-keys/my-key.pem`)
   - Application port: The port your application listens on (e.g., `3000`)
   - SSH port: Usually `22` unless you've changed it

## Step 6: Verify Deployment

After deployment completes:

1. Check if your application is accessible:
```bash
curl http://YOUR_EC2_PUBLIC_IP
```

2. Open in a browser:
   - Navigate to `http://YOUR_EC2_PUBLIC_IP`

3. SSH into the instance and check:
```bash
# Check Docker containers
ssh -i ~/.ssh/aws-keys/my-key.pem ec2-user@YOUR_EC2_PUBLIC_IP "docker ps"

# Check Nginx status
ssh -i ~/.ssh/aws-keys/my-key.pem ec2-user@YOUR_EC2_PUBLIC_IP "sudo systemctl status nginx"
```

## Common Issues & Solutions

### Connection Timeout
```
[ERROR] Failed to establish SSH connection
```

**Solution**: Check security group allows SSH from your IP address.

### Permission Denied
```
Permission denied (publickey)
```

**Solution**: Verify you're using the correct:
1. Username for your AMI
2. SSH key that matches the EC2 key pair
3. Key permissions (chmod 400)

### Container Not Running
```
Container is not running
```

**Solution**: Check container logs:
```bash
ssh -i ~/.ssh/aws-keys/my-key.pem ec2-user@YOUR_EC2_PUBLIC_IP "docker logs CONTAINER_NAME"
```

### Nginx 502 Bad Gateway
```
502 Bad Gateway
```

**Solution**: Ensure:
1. Container is running
2. Application is binding to 0.0.0.0 (not 127.0.0.1)
3. Application port matches Nginx configuration

## Cost Optimization

To minimize AWS costs:

1. Use t2.micro (free tier eligible)
2. Stop the instance when not in use:
```bash
aws ec2 stop-instances --instance-ids i-xxxxxxxxx
```

3. Start when needed:
```bash
aws ec2 start-instances --instance-ids i-xxxxxxxxx
```

4. Consider using Elastic IP to keep the same IP address

## Example Docker Application

If you need a simple test application, create a repository with this Dockerfile:

```dockerfile
FROM node:18-alpine

WORKDIR /app

RUN echo '{"name":"test-app","version":"1.0.0","main":"server.js"}' > package.json

RUN echo 'const http = require("http"); \
const server = http.createServer((req, res) => { \
  res.writeHead(200, {"Content-Type": "text/html"}); \
  res.end("<h1>Hello from Docker on AWS EC2!</h1>"); \
}); \
server.listen(3000, "0.0.0.0", () => console.log("Server running on port 3000"));' > server.js

EXPOSE 3000

CMD ["node", "server.js"]
```

This creates a simple Node.js web server listening on port 3000.