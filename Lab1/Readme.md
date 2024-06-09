# 312551086 Lab1
## Docker Environment
Step1. Install Docker-Desktop (Windows)

Step2. Download DockerFile and Docker Compose.yml and run cmd with **System Administrator**.
```
docker-compose up -d
```
There might have some error, maybe due to network problem which cause timeout, simply try several times to solve it. <BR>
ps. Not sure is sysadmin required, but less error appeared after running with it.

Step3. Connect to docker with ssh.
```
ssh -p {port} {username}@localhost
```