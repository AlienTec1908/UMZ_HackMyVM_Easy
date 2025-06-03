# UMZ - HackMyVM (Easy)

![umz.png](umz.png)

## Übersicht

*   **VM:** Umz
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Umz)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 3. Juni 2025
*   **Original-Writeup:** https://alientec1908.github.io/UMZ_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Die Challenge "Umz" ist eine als "Easy" eingestufte virtuelle Maschine von der Plattform HackMyVM. Ziel ist es, zunächst Benutzerzugriff und anschließend Root-Rechte auf dem System zu erlangen. Der Lösungsweg beinhaltet die Entdeckung eines versteckten Web-Panels durch einen simulierten Server-Stress-Test, die Ausnutzung einer Command Injection Schwachstelle in diesem Panel für den initialen Zugriff und die anschließende Privilegienerweiterung durch Missbrauch einer SUID-gesetzten `dd`-Kopie.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `feroxbuster`
*   `nikto`
*   `vi` (oder anderer Texteditor)
*   `wfuzz`
*   `curl`
*   `ssh`
*   `sudo`
*   `find`
*   `md5sum`
*   `python3`
*   `perl`
*   Standard Linux-Befehle (`ls`, `cat`, `cp`, `echo`, `su`, `file`, `chmod`, `mkdir`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Umz" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   Identifizierung der Ziel-IP (`192.168.2.211`) mittels `arp-scan`.
    *   Umfassender Portscan mit `nmap` offenbarte offene Ports 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Apache 2.4.62). Auf Port 80 lief eine Webseite mit dem Titel "cyber fortress 9000" und Hinweisen auf eine Primzahlgenerierungsfunktion auf `index.php`.
    *   Hinzufügen eines Eintrags (`192.168.2.211 umz.hmv`) zur lokalen `/etc/hosts`-Datei.

2.  **Web Enumeration & Schwachstellensuche (Port 80):**
    *   `feroxbuster` auf Port 80 fand keine neuen relevanten Verzeichnisse außer den bekannten (`/`, `index.php`, `index.html`).
    *   `nikto` meldete fehlende Sicherheitsheader (X-Frame-Options, X-Content-Type-Options) und ein mögliches ETag-Inode-Leak.
    *   Ein `wfuzz`-Scan auf `index.php` identifizierte den Parameter `stress` als gültigen Eingabepunkt.
    *   Ein Versuch, PHP-Code über den `data://`-Wrapper mit dem `stress`-Parameter auszuführen, scheiterte, was auf `allow_url_include=Off` hindeutete.

3.  **Initial Access (Command Injection via verstecktem Web-Panel):**
    *   Ein simulierter Stress-Test mittels einer `curl`-Schleife auf `index.php?stress=[wert]` führte dazu, dass ein neuer Port (`8080`) auf dem Zielsystem geöffnet wurde.
    *   Ein `nmap`-Scan bestätigte den offenen Port 8080 (http-proxy).
    *   `feroxbuster` auf Port 8080 fand eine `/login`-Seite für ein "System Maintenance Panel".
    *   Erfolgreicher Login in das Panel mit den Standard-Credentials `admin:admin`.
    *   Identifizierung einer Command Injection Schwachstelle im Panel: Eingabe von `;[BEFEHL]` im Ping-Formular führte zur Ausführung des Befehls als Benutzer `welcome`.
    *   Auslesen der User-Flag mittels `;cat /home/welcome/user.txt`.

4.  **Post-Exploitation / Privilege Escalation (von `welcome` zu `umzyyds`):**
    *   Einrichtung des SSH-Zugangs für den Benutzer `welcome` durch Erstellen des `.ssh`-Verzeichnisses und Hinzufügen des eigenen Public Keys zur `authorized_keys`-Datei über die RCE.
    *   Erfolgreicher SSH-Login als `welcome`.
    *   `sudo -l` als `welcome` offenbarte, dass `/usr/bin/md5sum` ohne Passwort als Root ausgeführt werden kann.
    *   Im Verzeichnis `/opt/flask-debug/` wurde die Datei `umz.pass` (Eigentümer `root`, nur für `root` lesbar) gefunden.
    *   Mittels `sudo -u root /usr/bin/md5sum /opt/flask-debug/umz.pass` wurde der MD5-Hash des Inhalts von `umz.pass` erlangt (`a963fadd7fd379f9bc294ad0ba44f659`).
    *   Ein Python-Skript (`md5cracker.py`) wurde lokal erstellt, um den MD5-Hash (unter Annahme eines angehängten Newline-Zeichens) gegen `rockyou.txt` zu knacken. Das Passwort `sunshine3` wurde gefunden.
    *   Erfolgreicher Wechsel zum Benutzer `umzyyds` mit `su umzyyds` und dem Passwort `sunshine3`.

5.  **Privilege Escalation (von `umzyyds` zu root):**
    *   `sudo -l` als `umzyyds` zeigte keine `sudo`-Berechtigungen.
    *   Im Home-Verzeichnis von `umzyyds` wurde die Datei `Dashazi` gefunden, die `root:root` gehört und SUID/SGID-Bits gesetzt hat.
    *   `file Dashazi` und `./Dashazi --h` bestätigten, dass `Dashazi` eine Kopie des `dd`-Befehls ist.
    *   **Proof of Concept (Root):**
        *   Lesen der Root-Flag: `./Dashazi if=/root/root.txt of=/tmp/root_flag.txt` und anschließendes `cat /tmp/root_flag.txt`.
        *   Hinzufügen eines neuen Root-Users: Erstellen eines Passwort-Hashes (z.B. "dark" mit Passwort "toor" -> `aalIoK7SGUI2k`), Kopieren von `/etc/passwd` nach `/tmp/passwd.original`, Erstellen einer modifizierten Version `/tmp/passwd.modified` mit dem neuen User-Eintrag (`dark:aalIoK7SGUI2k:0:0:SuperUser:/root:/bin/bash`), und Zurückschreiben mit `./Dashazi if=/tmp/passwd.modified of=/etc/passwd`.
        *   Erfolgreicher Login als neuer Root-Benutzer `dark` mit `su dark` und dem Passwort `toor`.

## Wichtige Schwachstellen und Konzepte

*   **Versteckter Dienst durch Serverlast:** Ein ungewöhnlicher Mechanismus, bei dem ein neuer Netzwerkport (8080) erst nach simulierter Serverüberlastung geöffnet wurde.
*   **Standard-Anmeldeinformationen:** Das "System Maintenance Panel" auf Port 8080 war mit `admin:admin` zugänglich.
*   **Command Injection:** Die Ping-Funktion im Web-Panel war anfällig für Command Injection, was den initialen Shell-Zugriff als Benutzer `welcome` ermöglichte.
*   **Unsichere sudo-Regel:** Der Benutzer `welcome` konnte `/usr/bin/md5sum` als Root ausführen, was das Auslesen des MD5-Hashes einer root-eigenen Passwortdatei (`umz.pass`) ermöglichte.
*   **Schwaches Passwort / MD5-Hashing:** Das Passwort `sunshine3` (für `umzyyds`), das in `umz.pass` gespeichert war und dessen MD5-Hash erlangt wurde, konnte leicht geknackt werden.
*   **SUID/SGID Missbrauch (`dd`):** Eine Kopie des `dd`-Befehls (`Dashazi`) mit SUID/SGID-Root-Rechten im Home-Verzeichnis eines Benutzers erlaubte das Lesen und Schreiben beliebiger Dateien als Root und somit die vollständige Kompromittierung des Systems.

## Flags

*   **User Flag (`/home/welcome/user.txt`):** `flag{user-4483f72525b3c316704cf126bec02d5c}`
*   **Root Flag (`/root/root.txt`):** `flag{root-a73c45107081c08dd4560206b8ef8205}`

## Tags

`HackMyVM`, `Umz`, `Easy`, `Command Injection`, `SUID Exploit`, `dd Exploit`, `Password Cracking`, `Linux`, `Web`, `Privilege Escalation`
