"""
Author: Arnold Vianna
https://github.com/arnold-vianna
nmap cheat sheat gui
"""

import tkinter as tk
from tkinter import ttk

class CheatSheetApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap Cheat Sheet")
        self.root.configure(bg='black')

        # Open the window maximized
        self.root.attributes('-zoomed', True)
        
        # Add a title label
        title_label = tk.Label(self.root, text="Nmap Cheat Sheet", font=('Arial', 16, 'bold'), fg='green', bg='black')
        title_label.pack(pady=10)

        # Create a frame to organize widgets
        frame = ttk.Frame(self.root, style="My.TFrame")
        frame.pack(fill='both', expand=True)

        # Create a Treeview widget on the left
        self.tree = ttk.Treeview(frame, style="My.Treeview")
        self.tree.heading('#0', text='Topics', anchor='w')
        self.tree.column('#0', width=600)
        self.tree.pack(side='left', fill='y', padx=10, pady=10, expand=False)

        # Create a frame for the Text widget and scrollbar
        text_frame = ttk.Frame(frame)
        text_frame.pack(side='left', fill='both', expand=True, padx=10, pady=10)

        # Create a Text widget on the right with a vertical scrollbar
        self.text = tk.Text(text_frame, wrap='word', width=50, height=10, font=('Arial', 12), fg='green', bg='black')
        self.text.pack(side='left', fill='both', expand=True)

        # Add a vertical scrollbar to the Text widget
        scrollbar = ttk.Scrollbar(text_frame, command=self.text.yview, orient='vertical')
        scrollbar.pack(side='left', fill='y')
        self.text.config(yscrollcommand=scrollbar.set)

        # Create a search bar
        self.search_var = tk.StringVar()
        search_bar = tk.Entry(frame, textvariable=self.search_var, fg='green', bg='black')
        search_bar.pack(side='top', fill='x', padx=10, pady=5)
        search_bar.bind('<KeyRelease>', self.filter_tree)

        # Create a copy button
        copy_button = tk.Button(frame, text="Copy Command", command=self.copy_command, fg='green', bg='black')
        copy_button.pack(side='top', pady=5)

        # Configure tags for treeview item colors
        self.tree.tag_configure('mytag', background='black', foreground='green')

        # Dictionary to store topic-command mappings
        self.topic_commands = {
  "Scan a single IP": "nmap 192.168.1.1 ",
  "Scan specific IPs": "nmap 192.168.1.1 192.168.2",
  "Scan a range": "nmap 192.168.1.1-254",
  "Scan a domain": "nmap scanme.nmap.org",
  "Scan using CIDR notation": "nmap 192.168.1.0/24",
  "Scan targets from a file": "nmap -iL targets.txt",
  "Scan 100 random hosts": "nmap -iR 100",
  "010Exclude listed hosts101010": "nmap --exclude 192.168.1.1",
  "TCP SYN port scan (Default)": "nmap 192.168.1.1 -sS",
  "TCP connect port scan(Default without root privilege)": "nmap 192.168.1.1 -sT",
  "UDP port scan": "nmap 192.168.1.1 -sU",
  "TCP ACK port scan": "nmap 192.168.1.1 -sA",
  "TCP Window port scan": "nmap 192.168.1.1 -sW",
  "TCP Maimon port scan": "nmap 192.168.1.1 -sM",
  "No Scan. List targets only": "nmap 192.168.1.1-3 -sL",
  "Disable port scanning": "nmap 192.168.1.1/24 -sn",
  "Disable host discovery. Port scan only": "nmap 192.168.1.1-5 -Pn",
  "TCP SYN discovery on port x. Port 80 by default": "nmap 192.168.1.1-5 -PS22-25,80",
  "TCP ACK discovery on port x. Port 80 by default": "nmap 192.168.1.1-5 -PA22-25,80",
  "UDP discovery on port x. Port 40125 by default": "nmap 192.168.1.1-5 -PU53",
  "ARP discovery on local network": "nmap 192.168.1.1-1/24 -PR",
  "Never do DNS resolution": "nmap 192.168.1.1 -n",
  "Port scan for port x": "nmap 192.168.1.1 -p 21 ",
  "Port range": "nmap 192.168.1.1 -p 21-100",
  "Port scan multiple TCP and UDP ports": "nmap 192.168.1.1 -p U:53,T:21-25,80",
  "Port scan all ports": "nmap 192.168.1.1 -p-",
  "Port scan from service name": "nmap 192.168.1.1 -p http,https",
  "Fast port scan (100 ports)": "nmap 192.168.1.1 -F",
  "Port scan the top x ports": "nmap 192.168.1.1 --top-ports 2000",
  "Leaving off initial port in range makes the scan start at port 1": "nmap 192.168.1.1 -p-65535",
  "Leaving off initial port in range makes the scan start at port 1": "nmap 192.168.1.1 -p-65535",
  "Leaving off end port in range makes the scan go through to port 65535": "nmap 192.168.1.1 -p0-",
  "Attempts to determine the version of the service running on port": "nmap 192.168.1.1 -sV ",
  "Intensity level 0 to 9. Higher number increases possibility of correctness": "01010nmap 192.168.1.1 -sV --version-intensity 81010",
  "Enable light mode. Lower possibility of correctness. Faster010": "nmap 192.168.1.1 -sV --version-light",
  "Enable intensity level 9. Higher possibility of correctness. Slower": "nmap 192.168.1.1 -sV --version-all",
  "Enables OS detection, version detection, script scanning, and traceroute": "nmap 192.168.1.1 -A",
  "Remote OS detection using TCP/IP stack fingerprinting": "nmap 192.168.1.1 -O",
  "If at least one open and one closed TCP port are not found it will not try OS detection against host": "nmap 192.168.1.1 -O --osscan-limit",
  "Makes Nmap guess more aggressively": "nmap 192.168.1.1 -O --osscan-guess",
  "Set the maximum number x of OS detection tries against a targe": "nmap 192.168.1.1 -O --max-os-tries 1 ",
  "Enables OS detection, version detection, script scanning, and traceroute": "nmap 192.168.1.1 -A",
  "Paranoid (0) Intrusion Detection System evasion": "nmap 192.168.1.1 -T0",
  "Sneaky (1) Intrusion Detection System evasion": "nmap 192.168.1.1 -T1 ",
  "Polite (2) slows down the scan to use less bandwidth and use less target machine resources": "nmap 192.168.1.1 -T2",
  "Normal (3) which is default speed": "nmap 192.168.1.1 -T3",
  "Aggressive (4) speeds scans; assumes you are on a reasonably fast and reliable network": "nmap 192.168.1.1 -T4",
  "Insane (5) speeds scan; assumes you are on an extraordinarily fast network": "nmap 192.168.1.1 -T5",
  "Give up on target aer this long": "-host-timeout <time> 1s; 4m; 2h",
  "Specifies probe round trip time": "--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time> 1s; 4m; 2h",
  "Parallel host scan group sizes": "-min-hostgroup/max-hostgroup <size> 50; 1024",
  "Probe parallelization": "--min-parallelism/max-parallelism <numprobes> 10; 1",
  "Adjust delay between probes": "-scan-delay/--max-scan-delay <time> 20ms; 2s; 4m; 5h",
  "Specify the maximum number of port scan probe retransmissions": "-max-retries <tries> 3",
  "Send packets no slower than <number> per second": "--min-rate <number> 100",
  "Send packets no faster than <number> per second": "--max-rate <number> 100",
  "01010Scan with default NSE scripts. Considered useful for discovery and safe1010": "nmap 192.168.1.1 -sC",
  "Scan with default NSE scripts. Considered useful for discovery and safe": "nmap 192.168.1.1 --script default",
  "Scan with a single script. Example banner": "0101010nmap 192.168.1.1 --script=banner10",
  "Scan with a wildcard. Example http": "nmap 192.168.1.1 --script=http*",
  "Scan with two scripts. Example http and banner": "nmap 192.168.1.1 --script=http,banner",
  "Scan default, but remove intrusive scripts": "nmap 192.168.1.1 --script not intrusive",
  "Scan default, but remove intrusive scripts": "nmap 192.168.1.1 --script not intrusive",
  "NSE script with arguments": "nmap --script snmp-sysdescr --script-args snmpcommunity=admin 192.168.1.1",
  "http site map generator": "nmap -Pn --script=http-sitemap-generator scanme.nmap.org",
  "Fast search for random web servers": "nmap -n -Pn -p 80 --open -sV -vvv --script banner,http-title -iR 1000",
  "Brute forces DNS hostnames guessing subdomains": "nmap -Pn --script=dns-brute domain.com",
  "Safe SMB scripts to run": "01nmap -n -Pn -vv -O -sV --script smb-enum*,smb-ls,smb-mbenum,smb-os-discovery,smb-s*,smb-vuln*,smbv2* -vv 192.168.1.10101010",
  "Whois query": "nmap --script whois* domain.com",
  "Detect cross site scripting vulnerabilities.": "nmap -p80 --script http-unsafe-output-escaping scanme.nmap.org",
  "Check for SQL injections": "nmap -p80 --script http-sql-injection scanme.nmap.org",
  "Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters": "010nmap 192.168.1.1 -f101010",
  "Set your own offset size": "nmap 192.168.1.1 --mtu 32",
  "Send scans from spoofed IPs": "nmap -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1",
  "Send scans from other spoofed IPs": "nmap -D decoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip",
  "Scan Facebook from Microso (-e eth0 -Pn may be required)": "nmap -S www.microso.com www.facebook.com",
  "Use given source port number": "nmap -g 53 192.168.1.1",
  "Relay connections through HTTP/SOCKS4 proxies": "010nmap --proxies http://192.168.1.1:8080, http://192.168.1.2:8080 192.168.1.1101010",
  "Appends random data to sent packets": "nmap --data-length 200 192.168.1.1",
  "Normal output to the file normal.file": "nmap 192.168.1.1 -oN normal.file",
  "XML output to the file xml.file": "nmap 192.168.1.1 -oX xml.file",
  "Grepable output to the file grep.file": "nmap 192.168.1.1 -oG grep.file",
  "Output in the three major formats at once": "nmap 192.168.1.1 -oA results",
  "Grepable output to screen. -oN -, -oX - also usable": "nmap 192.168.1.1 -oG -",
  "Append a scan to a previous scan file": "nmap 192.168.1.1 -oN file.file --append-output",
  "Increase the verbosity level (use -vv or more for greater effect)": "nmap 192.168.1.1 -v",
  "Increase debugging level (use -dd or more for greater effect)": "nmap 192.168.1.1 -d",
  "Display the reason a port is in a particular state, same output as -vv": "nmap 192.168.1.1 --reason",
  "Only show open (or possibly open) ports": "nmap 192.168.1.1 --open",
  "Show all packets sent and received": "nmap 192.168.1.1 -T4 --packet-trace",
  "Shows the host interfaces and routes": "nmap --iflist",
  "Resume a scan": "nmap --resume results.file",
  "Scan for web servers and grep to show which IPs are running web servers": "nmap -p80 -sV -oG - --open 192.168.1.1/24 | grep open",
  "Compare output from nmap using the ndiff": "ndiff scanl.xml scan2.xml",
  "Convert nmap xml files to html files": "xsltproc nmap.xml -o nmap.html",
  "Reverse sorted list of how oen ports turn up": "grep  open  results.nmap | sed -r 's/ +/ /g' | sort | uniq -c | sort -rn | less",
  "Enable IPv6 scanning": "nmap -6 2607:f0d0:1002:51::4",
  "nmap help screen": "nmap -h",
  "Discovery only on ports x, no port scan": "nmap -iR 10 -PS22-25,80,113,1050,35000 -v -sn",
  "Arp discovery only on local network, no port scan": "nmap 192.168.1.1-1/24 -PR -sn -vv",
  "Traceroute to random targets, no port scan": "nmap -iR 10 -sn -traceroute",
  "Query the Internal DNS for hosts, list targets only": "nmap 192.168.1.1-50 -sL --dns-server 192.168.1.1",
  "Brute-forcing HTTP basic auth": "nmap -p80 --script http-brute 192.168.1.1-50",
  "Provide own user/password list": "nmap -sV --script http-brute --script-args userdb=~/usernames.txt,passdb=~/passwords.txt 192.168.1.1",
  "Detect a web application firewall": "nmap -sV --script http-waf-detect,http-waf-fingerprint192.168.1.1",
  "Detect XST vulnerabilities (via HTTP TRACE method)": "nmap -sV --script http-methods,http-trace --script-argshttp-methods.retest 192.168.1.1",
  "Detect XSS vulnerabilities": "nmap -sV --script http-unsafe-output-escaping 192.168.1.1-50",
  "Finding default credentials": "nmap -sV --script http-default-accounts 192.168.1.1-50",
  "Finding exposed Git repos": "nmap -sV --script http-git 192.168.1.1-50",
  "Brute-force SMTP": "nmap -p25 --script smtp-brute 192.168.1.1-50",
  "Brute-force IMAP": "nmap -p143 --script imap-brute 192.168.1.1-50",
  "Brute-force POP3": "nmap -p110 --script pop3-brute 192.168.1.1-50",
  "Enumerate users": "nmap -p 25 --script=smtp-enum-users 192.168.1.1-50",
  "SMTP running on alternate port(s)": "nmap -sV --script smtp-strangeport 192.168.1.1-50",
  "Discovering open relays": "nmap -sV --script smtp-open-relay -v 192.168.1.1-50",
  "Find available SMTP commands": "nmap -p 25 --script=smtp-commands 192.168.1.1-50",
  "Brute-force MS SQL passwords": "nmap -p1433 --script ms-sql-brute 192.168.1.1-50",
  "Dump password hashes (MS SQL)": "nmap -p1433 --script ms-sql-empty-password,ms-sql-dump-hashes 192.168.1.1-50",
  "List databases (MySQL)": "nmap -p3306 --script mysql-databases --script-args mysqluser=[user],mysqlpass=[password] 192.168.1.1-50",
  "Brute-force MySQL passwords": "nmap -p3306 --script mysql-brute 192.168.1.1-50",
  "Root/Anonymous accounts with empty passwords": "nmap -p3306 --script mysql-empty-password 192.168.1.1-50",
  "Brute-force Oracle SIDs": "nmap -sV --script oracle-sid-brute <target>",
  "Identify MongoDB servers": "nmap -p27017 --script mongodb-info <target>",
  "Listing CouchDB databases": "nmap -p5984 --script couchdb-databases <target>",
  "Identify Cassandra databases": "nmap -p9160 --script cassandra-brute <target>",
  "Brute-force Redis passwords": "nmap -p6379 --script redis-brute <target>",
}

        # Add topics to the tree
        for i, (topic, command) in enumerate(self.topic_commands.items()):
            self.tree.insert('', 'end', text=topic, tags=('mytag',))

        # Bind the tree item selection to update the text widget
        self.tree.bind('<ButtonRelease-1>', lambda event: self.on_tree_select())

        # Define a custom ttk style for the frame
        ttk.Style().configure("My.TFrame", background='black')

        # Define a custom ttk style for the treeview
        ttk.Style().configure("My.Treeview",
                              background='black',
                              foreground='green',
                              fieldbackground='black',
                              highlightcolor='black',
                              highlightbackground='black',
                              borderwidth=0)

    def filter_tree(self, event):
        search_term = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())  # Clear the treeview
        for i, (topic, command) in enumerate(self.topic_commands.items()):
            if search_term in topic.lower():
                tags = ('mytag',)
                self.tree.insert('', 'end', text=topic, tags=tags)
        self.tree.bind('<ButtonRelease-1>', lambda event: self.on_tree_select())

    def copy_command(self):
        command_text = self.text.get('1.0', 'end-1c')  # Get command text without trailing newline
        self.root.clipboard_clear()
        self.root.clipboard_append(command_text)

    def on_tree_select(self):
        # Get the selected item in the tree
        selected_item = self.tree.selection()
        if selected_item:
            # Get the topic associated with the selected item
            topic = self.tree.item(selected_item, 'text')
            # Get the command associated with the selected topic from the dictionary
            command = self.topic_commands.get(topic, "")
            # Clear the text widget and insert the command
            self.text.delete('1.0', 'end')
            self.text.insert('1.0', command)

if __name__ == "__main__":
    root = tk.Tk()
    app = CheatSheetApp(root)
    root.mainloop()
