### Usefull links

[Развёртывание Indeed PAM 2.10, базовый курс.](https://edu.indeed-company.ru/mod/page/view.php?id=68) \
[Дистрибутив Indeed PAM 2.10.1](https://download.indeed-company.ru/s/q8zoOXIGhxhfR2q) \
[Дистрибутив Indeed PAM 2.10.3](https://download.indeed-company.ru/s/phaUY6BRU8fwi4O) \
[Документация Indeed PAM](https://docs.indeed-company.ru/privileged-access-manager/2.10/intro/) \
[База знаний](https://support.indeed-company.ru/Knowledgebase/List/Index/50/indeed-privileged-access-manager) 

---

### Install dependensies
```bash
sudo apt-get update && sudo apt-get install openssh-server nano htop zip unzip net-tools curl wget python3 python-is-python3 sudo iptables tcpdump ldap-utils -y
```
### Install docker
#### Debian
```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
```
#### РедОС / CentOS
```bash
# Install required packages
sudo dnf install -y yum-utils
# Add Docker's official GPG key
sudo rpm --import https://download.docker.com/linux/centos/gpg
# Add the repository to DNF sources
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
# Install Docker
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
# Unmask the Docker service and socket unit files
sudo systemctl unmask docker.service
sudo systemctl unmask docker.socket
# Start and enable the Docker service and socket
sudo systemctl enable docker.service --now
sudo systemctl enable docker.socket
```
#### Other's distro
https://docs.docker.com/engine/install/

### Install portainer (not essential)
<details><summary>Install portainer</summary>
  
```bash
sudo docker volume create portainer_data
sudo touch /var/run/docker.sock
sudo chmod 777 /var/run/docker.sock
```
```bash
sudo docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always -v "/var/run/docker.sock:/var/run/docker.sock" -v "portainer_data:/data" portainer/portainer-ce:2.21.0
```
from now you can access Portainer UI via `https://IP.address:9443` link
</details>

---
  
### Download Installer, Copy certs and configs to folders and start Deploy
Create `ca.crt`, `cert.pfx`, Edit and Prepare `vars.yml`, `config.json` and place them into `~home` directory
```bash
cd ~
```
```bash
wget -O IndeedPAM_2.10.3_RU.zip \
"https://download.indeed-company.ru/s/phaUY6BRU8fwi4O/download"
```
or
```bash
curl -L -o IndeedPAM_2.10.3_RU.zip \
"https://download.indeed-company.ru/s/phaUY6BRU8fwi4O/download"
```
```bash
unzip IndeedPAM_2.10.3_RU.zip
#we will add certs later
#cp ca.crt ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/state/ca-certificates/
#cp cert.pfx ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/state/certs/
cp vars.yml ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/scripts/ansible/
cp config.json ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/
cd ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/
```
<details><summary>vars.yml</summary>

```diff
selfsigned:
  ca_crt: "{{ selfsigned_dir }}/ca.crt"
  ca_key: "{{ selfsigned_dir }}/ca.key"
  info: "{{ selfsigned_dir }}/ca_info.yml"
  key_name: "pam-selfsigned.key"
  crt_name: "pam-selfsigned.crt"
  # Enable or disable automatic server certificate generation when certificates are not found or not valid
  # This setting does not affect pilot mode and access-server self-signed sertificates
- auto_gen: false
+ auto_gen: true
```
full config
```yml
---
# Default file and directory path variables
dest_path: "/etc/indeed/indeed-pam"
dest_img_temp: ".indeed/indeed-pam/deploy/"

config_file: "{{ data_dir }}/config.json"
state_dir: "{{ data_dir }}/state"
temp_dir: "{{ data_dir }}/temp"
selfsigned_dir: "{{ state_dir }}/selfsigned"
core_conf: "{{ state_dir }}/core/appsettings.json"
protector_conf: "{{ state_dir }}/tools/protector-appsettings.json"
wizard_api_conf: "{{ state_dir }}/web-wizard/config.prod.json"
img_path: "{{ data_dir }}/images/"
backup_dir: "{{ data_dir }}/backups"
sshkey_dir: "{{ state_dir }}/keys/ssh-proxy"
pam_user: "23041"
aa_profile_dir: "/etc/apparmor.d/indeed-pam"
gw_local_url: "http://gateway-service:8090/gw"

# Proxy protocol settings for haproxy configurations
# Send protocol setting
# To use version 1 set "send-proxy" (default)
# To use version 2 set "send-proxy-v2"
proxy_protocol_send: "send-proxy"
# Receive protocol setting
# "accept-proxy" detects both Proxy protocol versions
proxy_protocol_accept: "accept-proxy"

# Docker prune settings
prune:
  enabled: true
  cmd: "docker system prune -f"
  schedule: "Sat 23:00"

# Initial values of common variables
data_dir: "/pam-deploy"
tasks_dir: "{{ playbook_dir }}/tasks"
min_free_gb: 10
report_progress: true
pilot_mode: false

# Certificate generation related variables
ca_dir: "{{ state_dir }}/ca-certificates"
certs_dir: "{{ state_dir }}/certs"
rdp_dir: "{{ state_dir }}/keys/rdp-proxy"
ca_crt: "{{ ca_dir }}/ca.crt"
key_name: "pam.key"
crt_name: "pam.crt"

selfsigned:
  ca_crt: "{{ selfsigned_dir }}/ca.crt"
  ca_key: "{{ selfsigned_dir }}/ca.key"
  info: "{{ selfsigned_dir }}/ca_info.yml"
  key_name: "pam-selfsigned.key"
  crt_name: "pam-selfsigned.crt"
  # Enable or disable automatic server certificate generation when certificates are not found or not valid
  # This setting does not affect pilot mode and access-server self-signed sertificates
  auto_gen: true

# Uncomment the line below to use pfx passphrase
# pfx_pass: "ENTER_HERE"

# Uncomment the line below  to override public fqdn of host (used in certificate validation check)
# public_fqdn: "ENTER_HERE"

# Uncomment the line below to set virtual ip in multiple haproxy scenario
# vr_ip: "ENTER_HERE"

# Docker related variables
local_docker: "localhost"
compose_bin: "docker-compose"
tools_img: "indeed-pam-tools:latest"
daemon_json: "/etc/docker/daemon.json"
daemon_cfg:
  # By default, selinux-enabled parameter will be set to true if SELinux installed and enabled on the target hosts
  # Uncomment this line to override default behavior
  #"selinux-enabled": false
  "icc": false
  "live-restore": true
  "userland-proxy": false
  "no-new-privileges": true
# Uncomment lines below to configure remote logging in docker daemon
#  "log-driver": "syslog"
#  "log-opts":
#    "syslog-address": "udp://syslog-server-address:514"

# Container logging options, default "local"
docker_logging:
  driver: "local"
  options:
     max-size: "20m"
     max-file: "10"
# Use lines below to configure remote logging in compose files
# NOTE: multiple logging drivers is NOT supported
#  driver: "syslog"
#  options:
#    syslog-address: "udp://syslog-server-address:514"

# Use this option to enable rclone in management server, disable by default
# When setting this option to true, be sure to fill rclone config with run-storage-conf.sh
rclone_enabled: false
# Shared folder on remote media-data host, for example: pamshare/data
# Leave it empty to mount remote root directory
rclone_path: ""

# Docker bench for security
bench_log_dir: "{{ data_dir }}/logs/cis-benchmark"
bench_img: "nexus.indeed-id.hq:5050/pam/docker-bench-security:1.6.0"
bench_target_score: 15
bench_ignore: false

# Access server proxy recycling settings
proxy_recycling:
  enabled: false
  # Proxy types to recycle
  proxies: [rdp,ssh]
  # Master replica count
  replicas:
    rdp_proxy: 1
    ssh_proxy: 1
  # Rotation settings
  rotation_hours: 168
  session_hours: 24

# Inventory group docker related variables
images:
  access:
    - access
    - tools
  management:
    - management
    - nginx
    - tools
  haproxy:
    - haproxy

compose_files:
  access:
    - docker-compose.access-server.yml
  management:
    - docker-compose.management-server.yml
  haproxy:
    - docker-compose.management-server-haproxy.yml
    - docker-compose.access-server-haproxy.yml

state_files:
  access:
    - ca-certificates
    - keys/rdp-proxy
    - keys/ssh-proxy
    - keys/shared
    - logs/rdp
    - logs/ssh
    - logs/gateway-service
    - rdp-proxy
    - scripts
    - ssh-proxy
    - gateway-service
    - media-data
    - tools/protector-appsettings.json
    - tools/protector.sh
    - docker-compose.rdp-proxy.yml
    - docker-compose.ssh-proxy.yml
    - apparmor/pam-certs
    - apparmor/pam-gw-service
    - apparmor/pam-rdp-proxy
    - apparmor/pam-ssh-proxy
    - apparmor/pam-tools
    - media-data
    - media-temp
    - dumps
  management:
    - ca-certificates
    - core
    - idp
    - keys/idp
    - keys/shared
    - logs/core
    - logs/idp
    - logs/ls
    - logs/nginx
    - logs/mc
    - logs/uc
    - logs/rclone
    - ls
    - mc
    - nginx
    - scripts
    - uc
    - media-data
    - tools/protector-appsettings.json
    - tools/protector.sh
    - tools/migrator-appsettings.json
    - tools/migrator.sh
    - tools/dump-appsettings.json
    - tools/dump.sh
    - tools/key-rotator-appsettings.json
    - tools/key-rotator.sh
    - tools/stats-appsettings.json
    - tools/stats.sh
    - apparmor/pam-certs
    - apparmor/pam-nginx
    - apparmor/pam-management
    - apparmor/pam-ls
    - apparmor/pam-tools
  haproxy:
    - ca-certificates
    - haproxy
    - scripts
    - .env-haproxy
    - apparmor/pam-haproxy
    - apparmor/pam-keepalived
```
</details>

<details><summary>config.json</summary>

```json
{
  "DefaultServer": "TARGET_SERVER_FQDN", // к заполнению
  "DefaultDbServer": "pgsql",
  "DefaultDbUser": "admin",
  "DefaultDbPassword": "Q1w2e3r4",
  "IdpAdminSids": [
    "AD_ADMIN_SID" // к заполнению
  ],
 "CoreServiceStorageConfiguration": {
    "Type": "FileSystem",
    "Settings": {
    "Root": "/mnt/storage"
    }
  },
  "GatewayServiceStorageConfiguration": {
    "Type": "FileSystem",
    "Settings": {
    "Root": "/mnt/storage"
    }
  },
  "Database": "pgsql",
 "LogServerUrl": "http://ls:5080/api",
  "EncryptionKey": "3227cff10b834ee60ad285588c6510ea1b4ded5b24704cf644a51d2a9db3b7e5", // к заполнению
  "ActiveDirectoryDomain": "AD_FQDN", //к заполнению
  "ActiveDirectoryContainerPath": "USER_CONTAINER_DN", // к заполнению
  "ActiveDirectoryUserName": "AD_SERVICE_USER_NAME", // к заполнению
  "ActiveDirectoryPassword": "AD_SERVICE_USER_PASSWORD", // к заполнению
  "ActiveDirectorySsl": true, // или false
  "IsLinux": true,
  "ThreadPoolSize": 8,
  "Enable2faByDefault": true,
  "enableOrganizationalUnits": false
}
```
You can generate `Encryption key` by
`IndeedPAM_2.10.3_RU\indeed-pam-tools\key-gen\IndeedPAM.KeyGen.exe` - AES \
or
```bash
openssl rand -hex 32
```
</details>

```bash
sudo chmod 777 *.sh
sudo bash run-deploy.sh --bench-skip -vvv
```

---

<details><summary>Spoiler (If you want to pass Benchmark without skipping) - not necessary</summary>

### Fix Docker Bench for Security

```bash
IndeedPAM_2.10.3_RU/indeed-pam-linux/logs/cis-benchmark/local.docker.log
```
  
```bash
sudo -i
```

```bash
echo '{
  "debug": true,
  "log-level": "info",
  "storage-driver": "overlay2",
  "bip": "172.17.0.1/16",
  "iptables": true,
  "userns-remap": "default"
}' > /etc/docker/daemon.json

chown root:root /etc/docker/daemon.json
chmod 644 /etc/docker/daemon.json
```

```bash
echo '[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "overlayfs"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
    runtime_type = "io.containerd.runc.v2"
' > /etc/containerd/config.toml

chown root:root /etc/containerd/config.toml
chmod 644 /etc/containerd/config.toml
```

```bash
echo 'DOCKER_OPTS="--dns 8.8.8.8 --dns 8.8.4.4"' > /etc/default/docker

chown root:root /etc/default/docker
chmod 644 /etc/default/docker
```

```bash
mkdir -p /etc/sysconfig
echo '# /etc/sysconfig/docker
DOCKER_STORAGE_OPTIONS="--storage-driver=overlay2"
DOCKER_NETWORK_OPTIONS="--bip=172.17.0.1/16"
' > /etc/sysconfig/docker

chown root:root /etc/sysconfig/docker
chmod 644 /etc/sysconfig/docker
```

```bash
mkdir -p /etc/docker/certs.d
openssl req -newkey rsa:4096 -nodes -keyout /etc/docker/certs.d/server-key.pem -x509 -days 365 -out /etc/docker/certs.d/server-cert.pem -subj "/CN=localhost"
chown root:root /etc/docker/certs.d/server-key.pem /etc/docker/certs.d/server-cert.pem
chmod 400 /etc/docker/certs.d/server-key.pem
chmod 444 /etc/docker/certs.d/server-cert.pem
```
```bash
sudo apt-get install containerd runc -y
sudo autoremove
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
```
```bash
sudo systemctl restart docker
exit
```
### Run Deploing script
```bash
sudo bash run-deploy.sh -vvv
```
</details>

<details><summary>Spoiler (If you have problems with permissions while Deploying) - not necessary</summary>
  
### Fix permissons
```bash
sudo mkdir -p ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/temp
sudo mkdir -p ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/backups
sudo mkdir -p ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/logs
sudo mkdir -p ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/logs/cis-benchmark
sudo mkdir -p ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/state/selfsigned

sudo chmod 777 -R ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/temp
sudo chmod 777 -R ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/backups
sudo chmod 777 -R ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/logs/
sudo chmod 777 -R ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/state
```
</details>

---

### Warnings

On Debian 12 you will have visual bug - Docker Containers may look like `Unhealthy` while fully Healthy and Running.
You may ignore that.
<details><summary>Screenshot</summary>
  <img width="875" alt="image" src="https://github.com/user-attachments/assets/16cec3c1-7745-40d4-a002-63b769d8577f">
</details>

---

### Add Corporate certs or Generate Self-Signed certs and change default one (not essential)
<details><summary>For Prod. You can skip it for PoV/Pilot.</summary>
  
<details><summary>Spoiler (if you don't have corporate CA and cert)</summary>

[generate self-signed cert on windows](https://github.com/chelaxian/KB_IT_infosec_NET_chatgpt/blob/main/%D0%BE%D0%BF%D0%B5%D1%80%D0%B0%D1%86%D0%B8%D0%B8%20%D1%81%20%D1%81%D0%B5%D1%80%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%82%D0%B0%D0%BC%D0%B8/%D0%B3%D0%B5%D0%BD%D0%B5%D1%80%D0%B0%D1%86%D0%B8%D1%8F%20%D1%81%D0%B5%D1%80%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%82%D0%B0%20(powershell%20-%20windows).md)

```bash
openssl genrsa -out pam-ca.key 2048
openssl req -x509 -new -nodes -key pam-ca.key -subj "/CN=indeed-pam" -days 10000 -out pam-ca.crt
openssl genrsa -out pam.key 2048
nano server.conf
```
<details><summary>server.conf</summary>
  
```conf
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = RU
ST = Moscow
L = Moscow
O = Oblast
OU = PamUnit
CN = pam.domain.net

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = pam.domain.com
DNS.2 = domain.com

[ v3_ext ]
authorityKeyIdentifier=keyid,issuer:always
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=@alt_names
</details>
```
</details>

```bash
openssl req -new -key pam.key -out server.csr -config server.conf
openssl x509 -req -in server.csr -CA pam-ca.crt -CAkey pam-ca.key -CAcreateserial -out pam.crt -days 10000 -extensions v3_ext -extfile server.conf
```
</details>

rename certs as listed below and copy
```bash
cp pam-ca.crt /etc/indeed/indeed-pam/ca-certificates/
cp pam.crt /etc/indeed/indeed-pam/certs/pam.crt
cp pam.key /etc/indeed/indeed-pam/certs/pam.key
```
</details>

---

### Add LDAPS root CA + intermediate CA and check connection (not essential)
<details><summary>If you need to Change/Rotate passwords</summary>
  
```bash
cp ca1.cer /etc/indeed/indeed-pam/ca-certificates/ca1.crt #base64 (root CA)
cp ca2.cer /etc/indeed/indeed-pam/ca-certificates/ca2.crt #base64 (intermediate CA)
cat ca1.cer ca2.cer > /etc/indeed/indeed-pam/ca-certificates/ca-pem.crt
```
check with CURL ldaps connection
```bash
curl ldaps://dc1.domain.net --cacert /etc/indeed/indeed-pam/ca-certificates/ca-pem.crt
curl ldaps://domain.net --cacert /etc/indeed/indeed-pam/ca-certificates/ca-pem.crt
```
Curl should work both for DC and for DOMAIN. If curl for DOMAIN not work - you should create new Kerberos cert for LDAPS of your AD with 
```conf
[ alt_names ]
DNS.1 = dc.domain.com
DNS.2 = domain.com
```
[how to 1](https://docs.inno.tech/ru/linux-configuration-manager/latest/maintenance-guide/integrations/ad-integration/set-ldap-over-ssl/) \
[how to 2](https://winitpro.ru/index.php/2014/10/02/aktiviruem-ldap-over-ssl-ldaps-v-windows-server-2012-r2/)

---

### Change settings from LDAP to LDAPS
```bash
 nano /etc/indeed/indeed-pam/core/appsettings.json
 nano /etc/indeed/indeed-pam/idp/appsettings.json
```
<details><summary>appsettings.json</summary>

```diff
"Id": "ad",
"ConnectorType": "Ldap",
"LdapServerType": "ActiveDirectory",
"Domain": "domain.net",
-"Port": 389,
+"Port": 636,
"AuthType": "Basic",
-"SecureSocketLayer": false,
+"SecureSocketLayer": true,

```

</details>
</details>

---

### Commands to STOP / START / SET permissions after CHANGES in CONFIGS
```bash
bash /etc/indeed/indeed-pam/scripts/stop-pam.sh
bash /etc/indeed/indeed-pam/scripts/set-permissions.sh
bash /etc/indeed/indeed-pam/scripts/run-pam.sh
```

---

### Add /etc/hosts entry to docker containers
<details><summary>Spoiler (If needed)</summary>

`nano /etc/indeed/indeed-pam/docker-compose.management-server.yml`

```diff
  core:
    [...]
+    extra_hosts:
+      - "domain.net:10.x.x.x"

  idp:
    [...]
+    extra_hosts:
+      - "domain.net:10.x.x.x"
```
</details>

---
  
### Check LOGS to MONITOR and FIX ERRORS
```bash
 cd /etc/indeed/indeed-pam/logs/
 cat /etc/indeed/indeed-pam/logs/idp/errors.log
```

---

### Run Indeed-Wizard docker on same VM/server

<details><summary>Spoiler (for non-All-in-One installations - if you need to add Windows RDS or other PAM components)</summary>
\
  
0. stop PAM ant try to run wizard
   
```bash
sudo bash /etc/indeed/indeed-pam/scripts/stop-pam.sh
sudo bash ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/run-wizard.sh
```

1. if it not helps - rename docker container `pam-ca-certificates` to `pam-ca-certificates1`

2. ```nano ~/IndeedPAM_2.10.3_RU/indeed-pam-linux/state/docker-compose.web-wizard.yml```

```diff
    ports:
-      - "${HOST_IP}:80:8090"
-      - "${HOST_IP}:443:5443"
+      - "${HOST_IP}:8080:8090"
+      - "${HOST_IP}:8443:5443"
```
```diff
networks:
  default:
    name: pam-default-network
+    external: true
  web-wizard-api-network:
    name: pam-web-wizard-api-network
    driver: bridge

volumes:
  pam-ca-cert-store:
    name: pam-ca-cert-store
+    external: true
```
```bash
sudo ./run-wizard.sh -vvv
```
</details>

---

### Add RDS Windows Server (RemoteApp) to Linux PAM

<details><summary>Spoiler (If you need RemoteApp/Web)</summary>

```bash
 sudo bash /etc/indeed/indeed-pam/tools/protector.sh unprotect
```
Copy `"GatewaySecret": "XxXXXXXXXXxXXXXXXXXxXXXXXXXXXXXXXXxXxXXxXxx=",` string to \
`C:\Program Files\Indeed\Indeed PAM\Gateway\ProxyApp\appsettings.json` on Windows RDS server \
fill in Core and Auth(IDP) sections
<details><summary>appsettings.json</summary>
  
```json
{
  "Core": {
    "Url": "https://pam.domain.net/core",
    "RequestTimeout": "00:01:00"
  },
  "Auth": {
    "IdpUrl": "https://pam.domain.net/idp",
    "IdpRequiresHttps": true,
    "GatewaySecret": "XxXXXXXXXXxXXXXXXXXxXXXXXXXXXXXXXXxXxXXxXxx="
  },
```
```json
  "GatewayService": {
    "Url": "https://win-rds.domain.net:5443/"
```
</details>

Copy `"GatewaySecret": "XxXXXXXXXXxXXXXXXXXxXXXXXXXXXXXXXXxXxXXxXxx=",` string to \
`C:\Program Files\Indeed\Indeed PAM\Gateway\Pam.Gateway.Service\appsettings.json` \ 
on Windows RDS server and fill in Core and Auth(IDP) sections

<details><summary>appsettings.json</summary>
  
```json
  "Storage": {
    "Type": "SMB",
    "Settings": {
      "Root": "\\\\IP.IP.IP.IP\\IPAMStorage",
      "Domain": "FULL.DOMAIN.NAME",
      "Login": "USER",
      "Password": "PASSWORD"
```
add this lines to the end of file and check json
```json
}    
}
  },
  "Kestrel": {
    "Endpoints": {
      "HttpsInlineCertStore": {
        "Url": "https://0.0.0.0:5443",
        "Certificate": {
          "Subject": "win-rds.domain.net",
          "Store": "My",
          "Location": "LocalMachine",
          "AllowInvalid": "False"
        }
      }
    }
  }
}
```
</details>

full config
<details><summary>appsettings.json</summary>

```json
{
  "Local": {
    "MediaDataRootDirectory": "C:\\ProgramData\\Indeed\\Indeed PAM\\MediaTemp"
  },

  "Storage": {
    "Type": "SMB",
    "Settings": {
      "Root": "\\\\IP.IP.IP.IP\\IPAMStorage", //change me
      "Domain": "FULL.DOMAIN.NAME", //change me
      "Login": "USER", //change me
      "Password": "PASSWORD" //change me
   }
  },

  "Cors": {
    "AllowedOrigins": "*",
    "AllowedMethods": "*",
    "AllowedHeaders": "*"
  },

  "EnableSwagger": false,

  "NLog": {
    "variables": {
      "minLevel": "Info",
      "dbMinLevel": "Info"
    },
    "rules": {
      "1_StandardError": {
        "logger": "*",
        "minLevel": "Warn",
        "writeTo": "errorConsole",
        "enabled": false
      },
      "2_StandardOut": {
        "enabled": false,
        "logger": "*",
        "maxLevel": "Warn",
        "minLevel": "${minLevel}",
        "writeTo": "console"
      },

      // Copy all errors to separate file
      "20_Errors": {
        "logger": "*",
        "minLevel": "Error",
        "writeTo": "errorsFile"
      },

      // Write everything to single file with traceId
      // Skip non-critical Microsoft logs
      "50_MicrosoftAspNetCoreIgnored": {
        "logger": "Microsoft.AspNetCore.*",
        "maxLevel": "Info",
        "final": true
      },
      "50_MicrosoftExtensionsIgnored": {
        "logger": "Microsoft.Extensions.*",
        "maxLevel": "Info",
        "final": true
      },
      "51_SystemIgnored": {
        "logger": "System.*",
        "maxLevel": "Info",
        "final": true
      },
      "90_Full": {
        "logger": "*",
        "minLevel": "${minLevel}",
        "writeTo": "fullFile"
}    
}
  },
  "Kestrel": {
    "Endpoints": {
      "HttpsInlineCertStore": {
        "Url": "https://0.0.0.0:5443",
        "Certificate": {
          "Subject": "win-rds.domain.ru", //change me
          "Store": "My",
          "Location": "LocalMachine",
          "AllowInvalid": "False"
        }
      }
    }
  }
}
```
</details>

Add settings to `application.json` on linux
```bash
 nano /etc/indeed/indeed-pam/core/appsettings.json
 nano /etc/indeed/indeed-pam/gateway-service/appsettings.json
```

<details><summary>appsettings.json</summary>

```json
  "Storage": {
    "Type": "SMB",
    "Settings": {
      "Root": "\\\\IP.IP.IP.IP\\IPAMStorage",
      "Domain": "FULL.DOMAIN.NAME",
      "Login": "USER",
      "Password": "PASSWORD"
```
```bash
bash /etc/indeed/indeed-pam/scripts/stop-pam.sh
bash /etc/indeed/indeed-pam/scripts/set-permissions.sh
bash /etc/indeed/indeed-pam/scripts/run-pam.sh
```
</details>

Make [security settings](https://docs.indeed-company.ru/privileged-access-manager/2.10/security-recommendations/access-server-security-settings/)
```cmd
cd IndeedPAM_2.10.3_RU\Indeed-pam-windows\MISC\ConfigurationProtector\
```
```powershell
.\Pam.Tools.Configuration.Protector.exe apply-gateway-security
```
```powershell
.\Pam.Tools.Configuration.Protector.exe validate-gateway-security
```

#### Rename this file and restart RDS service

`C:\Program Files\Indeed\Indeed PAM\Gateway\ProcessCreateHook.sample`

to

`C:\Program Files\Indeed\Indeed PAM\Gateway\ProcessCreateHook`
<details><summary>screenshot</summary>
<img width="598" alt="image" src="https://github.com/user-attachments/assets/a283ac3a-cf1d-4021-b9ff-0a4aef94e717">
</details>


#### Allow Firewall for 5443 port
<details><summary>screenshot</summary>
<img width="338" alt="image" src="https://github.com/user-attachments/assets/82f78782-0c9e-47ea-9d2a-c8f6a411f442">
<img width="332" alt="image" src="https://github.com/user-attachments/assets/34598578-0ff2-4ffc-9c81-6671901405c2">
</details>

check from linux
```bash
curl -ik https://win-rds.domain.net:5443/ --cacert /etc/indeed/indeed-pam/ca-certificates/ca-pem.crt
```
check on windows
```cmd
netstat -an | findstr 5443
```
</details>

---

### FAQ

#### Typical Errors

1. FQDN should have CAPITAL letters like https://DOMAIN.example.com - should be https://domain.example.com
