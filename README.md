# LAB SetUp for CybserSecurity (Blue + Red)

## Disclaimer

- Please read the [DISCLAIMER.md](/DISCLAIMER.md) before using or referencing this content.

## Problem

- lets say you scan **`Windows OS`** (`vmware` / `virtualbox` / `other`) using **`nmap` tool** (**`kali`**)

- **`N.B`** Bydefault windows OS block **`icmp`** request (`ping`) for security. So you have to disable the windows firewall then `nmap` might show some ports.

- now after **`nmap`** where can i see the logs regarding this scan.

### Check logs

1. **Check Windows Event Logs:**

   - Open the Event Viewer
   - Press **`Win + R`** , type **`eventvwr.msc`** hit Enter.
  
     ```bash
     Event Viewer → Windows Logs → Security
     ```

     or

     ```bash
     Event Viewer → Windows Logs → System
     ```

     or

     ```bash
     Applications and Services Logs → Microsoft → Windows → Windows Defender Firewall With Advanced Security → Firewall
     ```

2. **What to Look For:**

   - **Event ID `5152`** — Packet was blocked by Windows Filtering Platform

   - **Event ID `5156`** — Connection was allowed

   - **Event ID `5157`** — Connection attempt was blocked

   - **Event ID `4688`** — New process created (maybe triggered by exploitation)

   - **Event ID `4624` / `4625`** — Login attempts (if the scan tries creds)

   - These logs will tell you when a connection attempt happened, whether it was allowed or blocked, and which IP tried it.

3. **Turn on Firewall Logging (Optional but awesome):**

   - You can explicitly log dropped or successful connections.

   - Steps:

     1. Open **`Windows Defender Firewall`** with **`Advanced Security`**

     2. Click **`Properties`**

     3. Go to the **`Private Profile` (or the `one your VM is on`)**

     4. Under **`Logging`, `click Customize`…**

     5. Set:

        - Log dropped packets: **`Yes`**

        - Log successful connections: **`Yes`**

        - Set log path:
  
         ```bash
         C:\Windows\System32\LogFiles\Firewall\pfirewall.log
         ```

- Now try scanning again and check that file for logs.

### Output of Windows event logs (in my Vm)

| Event ID | Source                  | Meaning                                                                                     |
|----------|-------------------------|---------------------------------------------------------------------------------------------|
| 7040     | Service Control Manager | A service change was made (e.g., service start type changed).                               |
| 8033     | NetBT                   | Name release on the network. This happens when NetBIOS name registration changes — common in local network activity. |
| 1014     | DNS Client Events       | DNS resolution issue (timeout or unreachable DNS server).                                   |
| 10016    | DistributedCOM          | A DCOM app tried to access system components it doesn’t have permission for — noisy, but not a threat unless exploited. |

### So… Where’s the Scan?

- These events are more **`system`** or **`network-related background noise`** — they’re not direct evidence of your **`Nmap scan`**.

- To catch your **`Nmap`** scan specifically, you need to enable Firewall connection logging or use **`Sysmon`** + a **`SIEM`** for deeper visibility.

## Blue Team Tools for Monitoring & Defense on Windows

- **`Sysmon` (`System Monitor`) — Core for Visibility**

  - From **`Sysinternals` (`Microsoft`)**.

  - **`Logs`:** `process creation`, `network connections`, `file changes`, `registry mods`.

  - Works like **`EDR light`**.

- **`Event Viewer` (`Built-in`)**

  - Always keep an eye on:

    - **`Security logs` (`logins`, `process creation`)**

    - **`System logs`**

    - **`Firewall logs`**

    - **`AppCrash logs`**

- **`Windows Defender Firewall Logging`**

  - Enable dropped/successful connections logging:

    ```bash
    C:\Windows\System32\LogFiles\Firewall\pfirewall.log
    ```

- **`Windows Performance Monitor` / `Resource Monitor`**

  - Use **`resmon.exe`** or **`perfmon.msc`** to view:

    - **`Open ports`**

    - **`Active connections`**

    - **`CPU`, `memory`, `disk usage during an attack`**

- **`Process Monitor` (`Procmon`)**

  - **`Real-time`, `low-level monitoring` of:**

    - **`Registry`**

    - **`File system`**

    - **`Processes`**

    - **Great for catching `persistence techniques` or `malware behavior`.**

- **TCPView**

  - **GUI to watch `real-time network connections`.**

    - Like **`netstat`** on **`steroids`**.

- **Autoruns**

  - See all **`autostart locations`**.

  - **Catch `malware persistence` (`registry`, `scheduled tasks`, `services`)**.

- **`Wireshark` (`optional`, `advanced packet capture`)**

  - Analyze **`packets`** during attacks

  - Helps correlate events with **`real traffic`**

## Lets Build Lab with `Wazuh` + `Sysmon`

### How `Wazuh` + `Sysmon` Work Together

| Tool         | Purpose                                                                                           | Role in Detection                  |
|--------------|---------------------------------------------------------------------------------------------------|------------------------------------|
| **`Sysmon`** | Logs detailed system events (**`process creation`, `network connections`, `file changes`, etc.**) | Acts like an **`EDR agent`**       |
| **`Wazuh`**  | **`Collects`, `analyzes`, and `correlates` logs from `Sysmon`, `Windows Event Logs`, etc.**       | Acts like a **`SIEM engine`**      |

## Step-by-Step: Install Sysmon on Windows 10

### Download `Sysmon`

- Get it from the `official Microsoft Sysinternals` site:
  
  - [Click here to download]( https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

- Download the ZIP file and extract it.

  - Inside you’ll find:

    - **`Sysmon.exe` – for `32-bit`**

    - **`Sysmon64.exe` – for `64-bit`**

### Download a Good Configuration File

- Use this pre-built config (recommended by most professionals):

  - [Download confuguration file](https://github.com/SwiftOnSecurity/sysmon-config)

- Click **`"Code"` → `Download ZIP` or `clone` using `Git`**.
  
- Unzip it and find the file:

  - **`sysmonconfig-export.xml`**

### Install `Sysmon` with Config

- Open **`Command Prompt` as `Administrator` and `run`:**
  
  ```bash
  cd path\to\extracted\Sysmon
  Sysmon64.exe -accepteula -i path\to\sysmonconfig-export.xml
  ```

  Example

  ```bash
  Sysmon64.exe -accepteula -i C:\Users\YourName\Downloads\sysmonconfig-export.xml
  ```

### Verify `Sysmon` Is Running

```bash
sc query sysmon64
```

- You should see **`STATE: RUNNING`**.

### Check `Sysmon Logs`

- **`Sysmon logs` go to `Event Viewer` under:**

- **`Applications and Services Logs`** > **`Microsoft`** > **`Windows`** > **`Sysmon`** > **`Operational`**

### Next Moves (Highly Recommended)

### Trigger Some `Events`

- Opening **`cmd`** or **`powershell`**

  ```bash
  ping 8.8.8.8
  whoami
  notepad
  curl http://example.com
  ```

- These should generate **`events`** like:

  - **`Event ID` `1` (`Process Create`)**

  - **`Event ID` `3` (`Network Connection`)**

  - **`Event ID` `11` (`FileCreate`)**

### Open `Logs` and `Check`

- In Event Viewer, click **`"Operational"`**

- Check for entries like:

  - **`Event ID` `1`: `A process was created`**

  - **`Event ID` `3`: `Network connection made`**

  - **`Event ID` `10`: `Process accessed another process` (`for injection detection`)**

- You’ll see details like:

  - **`Image path`**

  - **`Command line`**

  - **`Parent process`**

  - **`Source IP`/`port` (`for network`)**

### Hook it to `Wazuh`

- If you set up **`Wazuh`** as **`SIEM`**, it’ll collect these **`logs`** and:

  - **Alert on `suspicious behaviors`**

  - **Give you a `beautiful dashboard`**

- **N.B**: `raw Event Viewer is like reading The Matrix` thats why we are hooking **`Sysmon`** to **`wazuh` (`free open-source SIEM tool`)**

## Overview of What We’re Building

```bash
[ Windows 10 VM ]
   └── Sysmon (collects rich logs)
   └── Wazuh Agent (forwards logs)

[ Ubuntu VM ]
   └── Wazuh Manager (SIEM brain)
   └── ElasticSearch + Kibana (dashboard + search)
```

## Set Up Wazuh (Manager + Dashboard)

- Choose Where to Host Wazuh
  
  - I chose Ubuntu VM

  - make sure it needs at least 4GB RAM, 2 CPU cores

- go to official website
  
  - [Wazuh](https://documentation.wazuh.com/current/quickstart.html)

### Installation process

- Open terminal
  
  ```bash
  curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
  ```

  then

  ```bash
  sudo bash ./wazuh-install.sh -a
  ```

- wait for the installation to finish.

- Now use pfficial Recommended Action: `Disable Wazuh Updates`
  
  ```bash
  sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list
  apt update
  ```

- After installation complete you'll see
  
  ```bash
  https://<wazuh-dashboard-ip>:443
  User: admin
  Password: <ADMIN_PASSWORD>
  ```

  here `<wazuh-dashboard-ip>` is your Ubuntu ip

- Now open browser and type `https://<wazuh-dashboard-ip>:443` but it will show its **`not secure`** click **`advance`** and continue website.
  
- You'll see a form then enter your username and password and you'll see `Wazuh dashboard`.

- Now you need to add **`Wazuh agent`** inorder to connect with your **`Wazuh Dasboard`**.

## Add Wazhu agent for Windows Machine

- To connect Wazuh agent to Wazhu dasboard you need authentication key. lets see how to generate and connect with Wazhu agent

- Open terminal in Ubuntu(where you install the Wazhu manager)
  
  ```bash
  sudo /var/ossec/bin/manage_agents
  ```

- You’ll see an interactive menu like this:
  
  ```bash
  ****************************************
  * Wazuh v4.11.2 Agent manager.         *
  * The following options are available: *
  ****************************************
   (A)dd an agent (A).
   (E)xtract key for an agent (E).
   (L)ist already added agents (L).
   (R)emove an agent (R).
   (Q)uit.

  ```

- Next **Choose option `A` for create new agent**

  ```bash
  Choose your action: A,E,L,R or Q: A

  - Adding a new agent (use '\q' to return to the main menu).
  Please provide the following:
   * A name for the new agent: name of ur agent (ex. win10-exploit-vm)
   * The IP Address of the new agent: <Ip address of your windows machine (ex. 198.165.191.121)>
  Confirm adding it?(y/n): y
  Agent added with ID 001.
  ```

- Next **Choose `E` to Generate `authentication key` for Created agent**
  
  ```bash
  Choose your action: A,E,L,R or Q: E

  Available agents: 
   ID: 001, Name: win10-exploit-vm, IP: 198.165.191.121
  Provide the ID of the agent to extract the key (or '\q' to quit): 001 #Provide ID of available agent
  ```

  **`Authentication key`** will generate

  ```bash
  Agent key information for '001' is: 
  mcuwywgjyIHdpbjEwLWV4cGxvaXQtdm0xIDE5Mi4xMjEuMTIyLjEgMTgxNGUxNWUyN2FlNj23dIyOTIzZGRmYWNhNzA5MzY2NTUwNWQ3MjhmOTQyNGYwMWmdjdks0NjAxZDE0OWNhZA==
  ```

- Now we are done. lets install **`Wazuh agent` for `Windows 10 machine`** where we installed **`symon`** and coonect with our **`Wazhu manager` (`Ubuntu`)**

## Install Wazuh Agent on Windows 10

- Download from official Wazuh website
  
  - [Windows Agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)

  - You can choose other agents of your choice.but here i am using `windows`

- After installation You'll see pop windows like below
  
  - ![Windows agent](/windows-agent.png)

- Here add **`Manager IP` (Ubuntu IP)** and **`Authentication key`** that we generated while creating **`agent`**.

- Now **`Save`**

- Click **`Manage`** and **`Start the Servce`** and **`Refresh`**
  
### Check Wazuh service is running or not

- Open **`PowerShell`** as **`Administrator`** and run:
  
  ```bash
  PS C:\Windows\system32> NET START WazuhSvc
  ```

- Check running status
  
  ```bash
  PS C:\Windows\system32> Get-Service WazuhSvc

  Status   Name               DisplayName
  ------   ----               -----------
  Running  WazuhSvc           Wazuh
  ```

### All Done Now Our `Wazuh agent` on(`Windows 10`) now connected to our `Wazuh manager` on (`Ubuntu`) and its Up and Running

## Final Step

- Open **`Wazuh Manager`** on **`Ubuntu`** and Open **`dashboard`** with your **`login credentials`** like **`username` and `password`**

- In HomePage You'll see **`Active`** in **`Agent Summary`**
  
![Agent Connected](/Wazuh-dashboard1.png)

- Click **`Active`**

![Agent](/Wazuh-dashboard2.png)

- Now Its connect and You'll see all logs will be show here from windows 10 machine.

## My Final Lab Setup (Clean & Efficient)

| VM                                     | Purpose                                            | Tools                                 |
|----------------------------------------|----------------------------------------------------|---------------------------------------|
| 🟥 **`Kali Linux`**                    | **`Red team attacker` (`send payloads`, `scan`)** | **`Nmap`, `Metasploit`, etc.**         |
| 🟦 **`Windows 10` (`Exploit Target`)** | **`Blue team endpoint` (`log everything`)**       | **`Sysmon` + `Wazuh Agent`**           |
| 🟨 **`Ubuntu` (`Log Analyzer`)**       | **`SIEM` + `Dashboard server`**                   | **`Wazuh Manager` + `ES` + `Kibana`**  |
