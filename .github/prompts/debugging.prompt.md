Let's do some debugging:

# Note for Debugging

## URL of app: 
https://unified-dev-6767.sableservers.com - publicly accessible URL.

## SSH = Enabled - SSH access is available for all developers to connect to the server and perform debugging tasks. SSH can be used to upload the latest code changes, run commands, check logs, and perform other debugging activities on the server. The SSH credentials for the variousservers are as follows:

Linux Dev Machines (SSH Access to Server): ssh root@<IP_ADDRESS>:<PORT> - For file upload, command execution, and debugging on the server.

### Dev Panel - WWWROOT is /var/www/sableservers
host:198.50.121.27
port: 2222
username: root
password: (PWD will be provided when prompted)

### HyperVisor Bare Metal Server
host: 208.69.79.234
port: 22
username: root
password: (PWD will be provided when prompted)

#### Game Server VM Information:
host: 208.69.79.46
port: 22
username: root
password: (PWD will be provided when prompted)

#### Web Hosting VM Information:
host: 198.50.121.28
port: 22
username: root
password: (PWD will be provided when prompted)

## Dev Aid/Addons

- Debugging in Firefox and Firefox Developer Edition available in VSCODE.
- All developers are operating systems are either Windows(3 users) or Linux(Debian based, 1 user). No MacOS.
- All developers have admin access to the server and can use SSH to connect to the server for debugging purposes.
- The Linux dev machines have the same OS (Debian 12 and Debian 13) as the server, so they can use similar tools and commands for debugging. The Windows dev machines do not use WSL (Windows Subsystem for Linux), so they may have to use different tools or commands for debugging. However, they can still use SSH to connect to the server and run commands remotely for debugging purposes.
- The Linux dev machines have Firefox installed with Debugging Extensions (Debugging For Firefox) configured(see .vscode/launch.json, Launch option configured), so they can use the Firefox Developer Tools for debugging the web application. Not all Windows dev machines have Firefox installed, so they may have to use a different browser or tool for debugging the web application. However, they can still use SSH to connect to the server and run commands remotely for debugging purposes.
