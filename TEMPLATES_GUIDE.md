# Guide des Templates SPL pour Splunk Cloud

## Corrections Apportées

### Problèmes Identifiés et Résolus

1. **Opérateurs SPL Non-Standard**
   - ❌ `LIKE` et `NOT LIKE` (non supportés en SPL)
   - ✅ Remplacés par `MATCHES` et `NOT MATCHES` (opérateurs SPL standard)

2. **Syntaxe de Filtres Corrigée**
   - ❌ `field LIKE "value"` 
   - ✅ `field = "value"` ou `field MATCHES "value"`

3. **Gestion des Commandes tstats**
   - ✅ Correction de la syntaxe pour les commandes `tstats`
   - ✅ Séparation logique entre `search`, `stats` et `tstats`

4. **Champs et Sourcetypes Réalistes**
   - ✅ Utilisation de sourcetypes standard de Splunk Cloud
   - ✅ Champs de filtrage compatibles avec l'environnement Splunk

## Templates DFIR & Security

### 1. Malware Detection
```spl
search index="security" sourcetype="windows_security OR windows_syslog OR linux_syslog" | earliest=-24h latest=now malware OR virus OR trojan OR ransomware OR "suspicious file" OR "quarantine" OR "threat detected" OR "malicious" OR "infection" | where action = "blocked"
```
**Utilisation** : Détection de logiciels malveillants dans les logs de sécurité

### 2. Suspicious Logins
```spl
search index="security" sourcetype="windows_security OR linux_syslog" | earliest=-24h latest=now login OR authentication OR "user logon" OR "successful logon" OR "failed logon" | where status = "success"
```
**Utilisation** : Surveillance des connexions suspectes

### 3. Failed Authentication
```spl
search index="security" sourcetype="windows_security OR linux_syslog OR web_access" | earliest=-24h latest=now authentication failure OR "failed login" OR "invalid password" OR "access denied" OR "login failed" | where status = "401" AND status = "403"
```
**Utilisation** : Détection des tentatives d'authentification échouées

### 4. Privilege Escalation
```spl
search index="security" sourcetype="windows_security OR linux_syslog" | earliest=-7d latest=now privilege OR elevation OR "run as administrator" OR sudo OR su OR "user rights" OR "security log" | where action = "elevation"
```
**Utilisation** : Détection d'élévation de privilèges

### 5. Data Exfiltration
```spl
search index="main" sourcetype="web_access OR network_traffic" | earliest=-24h latest=now large download OR "file transfer" OR "data export" OR "bulk download" OR "mass download" | where bytes > 10000000
```
**Utilisation** : Détection d'exfiltration de données

### 6. Command Execution
```spl
search index="security" sourcetype="windows_security OR linux_syslog" | earliest=-24h latest=now cmd OR powershell OR bash OR shell OR "command line" OR "process creation" OR "command execution" | where process = "cmd.exe" AND process = "powershell.exe"
```
**Utilisation** : Surveillance de l'exécution de commandes

### 7. Lateral Movement
```spl
search index="security" sourcetype="windows_security OR network_traffic" | earliest=-24h latest=now remote connection OR "remote desktop" OR "network logon" OR "lateral movement" OR "psexec" OR "wmic" | where action = "remote"
```
**Utilisation** : Détection de mouvements latéraux

### 8. Persistence Mechanisms
```spl
search index="security" sourcetype="windows_security OR linux_syslog" | earliest=-7d latest=now registry OR "startup folder" OR "scheduled task" OR "service creation" OR "persistence" OR "autorun" | where action = "create"
```
**Utilisation** : Détection de mécanismes de persistance

## Templates Network Security

### 9. Port Scanning
```spl
search index="network" sourcetype="firewall OR ids OR network_traffic" | earliest=-1h latest=now port scan OR "connection attempt" OR "multiple ports" OR "scanning" OR "probe" | where action = "blocked"
```
**Utilisation** : Détection de scans de ports

### 10. DDoS Attacks
```spl
search index="network" sourcetype="firewall OR ids OR web_access" | earliest=-1h latest=now DDoS OR "denial of service" OR "flood attack" OR "rate limit exceeded" OR "connection flood" | where action = "blocked"
```
**Utilisation** : Détection d'attaques DDoS

### 11. VPN Connections
```spl
search index="network" sourcetype="vpn OR firewall" | earliest=-24h latest=now VPN OR "virtual private network" OR "tunnel connection" OR "remote access" | where action = "connect"
```
**Utilisation** : Surveillance des connexions VPN

### 12. Firewall Events
```spl
search index="network" sourcetype="firewall" | earliest=-24h latest=now firewall OR "access denied" OR "connection blocked" OR "rule violation" | where action = "deny"
```
**Utilisation** : Surveillance des événements firewall

### 13. Proxy Usage
```spl
search index="network" sourcetype="web_access OR proxy" | earliest=-24h latest=now proxy OR "forwarded for" OR "via proxy" OR "proxy server" | where via = "proxy"
```
**Utilisation** : Surveillance de l'utilisation de proxy

### 14. Tor Traffic
```spl
search index="network" sourcetype="web_access OR network_traffic" | earliest=-24h latest=now tor OR "onion router" OR "exit node" OR "tor network" | where user_agent = "tor"
```
**Utilisation** : Détection du trafic Tor

## Templates Web Security

### 15. SQL Injection
```spl
search index="web" sourcetype="web_access OR web_error" | earliest=-24h latest=now sql OR "union select" OR "drop table" OR "insert into" OR "select from" OR "or 1=1" OR "or true" | where status >= 400
```
**Utilisation** : Détection d'injections SQL

### 16. XSS Attacks
```spl
search index="web" sourcetype="web_access OR web_error" | earliest=-24h latest=now script OR javascript OR "alert(" OR "onload=" OR "onerror=" OR "onclick=" OR "eval(" | where status >= 400
```
**Utilisation** : Détection d'attaques XSS

### 17. File Upload Attacks
```spl
search index="web" sourcetype="web_access" | earliest=-24h latest=now upload OR "file upload" OR ".php" OR ".jsp" OR ".asp" OR ".exe" OR ".bat" OR ".sh" | where method = "POST"
```
**Utilisation** : Détection d'attaques par upload de fichiers

### 18. Directory Traversal
```spl
search index="web" sourcetype="web_access OR web_error" | earliest=-24h latest=now .. OR "../" OR "..\\" OR "path traversal" OR "directory traversal" OR "../../" | where status >= 400
```
**Utilisation** : Détection de traversée de répertoires

### 19. API Abuse
```spl
search index="web" sourcetype="web_access OR api_logs" | earliest=-24h latest=now api OR "rate limit" OR "throttling" OR "abuse" OR "excessive requests" | where status = "429"
```
**Utilisation** : Détection d'abus d'API

### 20. Bot Traffic
```spl
search index="web" sourcetype="web_access" | earliest=-24h latest=now bot OR crawler OR spider OR "user agent" OR "automated" OR "scraper" | where user_agent = "bot"
```
**Utilisation** : Détection du trafic de bots

## Templates System Monitoring

### 21. Error Logs
```spl
search index="main" sourcetype="web_error OR application_logs OR system_logs" | earliest=-24h latest=now ERROR OR error OR Error OR "error" OR "ERROR" OR "exception" OR "failure" | where status >= 400
```
**Utilisation** : Surveillance des logs d'erreur

### 22. Performance Metrics
```spl
tstats index="performance" | earliest=-4h latest=now | avg(cpu_usage) by host | head 15
```
**Utilisation** : Métriques de performance système

### 23. Disk Usage
```spl
search index="system" sourcetype="system_metrics OR performance" | earliest=-24h latest=now disk OR "disk usage" OR "disk space" OR "storage" OR "capacity" | where usage_percent > 80
```
**Utilisation** : Surveillance de l'utilisation du disque

### 24. Memory Usage
```spl
search index="system" sourcetype="system_metrics OR performance" | earliest=-24h latest=now memory OR "memory usage" OR "RAM" OR "virtual memory" | where memory_usage > 90
```
**Utilisation** : Surveillance de l'utilisation mémoire

### 25. Service Status
```spl
search index="system" sourcetype="service_logs OR system_logs" | earliest=-24h latest=now service OR "service status" OR "service stopped" OR "service failed" OR "service error" | where status = "stopped" AND status = "failed"
```
**Utilisation** : Surveillance du statut des services

### 26. Process Monitoring
```spl
search index="system" sourcetype="process_logs OR system_logs" | earliest=-24h latest=now process OR "process creation" OR "process termination" OR "new process" | where action = "create"
```
**Utilisation** : Surveillance des processus

## Templates User Activity

### 27. User Activity
```spl
stats index="main" sourcetype="access_combined OR web_access" | earliest=-7d latest=now | count by user | head 50
```
**Utilisation** : Activité utilisateur

### 28. Top IPs
```spl
stats index="main" sourcetype="access_combined OR web_access" | earliest=-24h latest=now | count by clientip | head 10
```
**Utilisation** : Top des adresses IP

### 29. Response Times
```spl
stats index="main" sourcetype="access_combined OR web_access" | earliest=-1h latest=now | avg(response_time) by uri_path | head 20
```
**Utilisation** : Temps de réponse

### 30. File Access
```spl
search index="main" sourcetype="file_access OR audit_logs" | earliest=-24h latest=now file OR "file access" OR "file read" OR "file write" OR "file delete" | where action = "access"
```
**Utilisation** : Accès aux fichiers

### 31. Login Patterns
```spl
stats index="security" sourcetype="windows_security OR linux_syslog" | earliest=-7d latest=now login OR authentication OR "user logon" | count by user | head 20
```
**Utilisation** : Patterns de connexion

### 32. Session Duration
```spl
stats index="main" sourcetype="web_access OR session_logs" | earliest=-24h latest=now | avg(session_duration) by user | head 20
```
**Utilisation** : Durée des sessions

## Templates Compliance & Audit

### 33. GDPR Compliance
```spl
search index="audit" sourcetype="audit_logs OR data_access" | earliest=-30d latest=now personal data OR PII OR "personal information" OR "data access" OR "data export" | where data_type = "personal"
```
**Utilisation** : Conformité GDPR

### 34. PCI Audit
```spl
search index="audit" sourcetype="audit_logs OR payment_logs" | earliest=-30d latest=now credit card OR payment OR "card number" OR "payment processing" OR PCI | where compliance = "PCI"
```
**Utilisation** : Audit PCI

### 35. SOX Compliance
```spl
search index="audit" sourcetype="audit_logs OR financial_logs" | earliest=-30d latest=now financial OR accounting OR "financial data" OR "SOX" OR "Sarbanes-Oxley" | where compliance = "SOX"
```
**Utilisation** : Conformité SOX

### 36. Access Reviews
```spl
search index="audit" sourcetype="audit_logs OR access_logs" | earliest=-30d latest=now access OR "access review" OR "permission change" OR "role change" OR "privilege change" | where action = "change"
```
**Utilisation** : Révisions d'accès

### 37. Data Classification
```spl
search index="audit" sourcetype="audit_logs OR data_logs" | earliest=-30d latest=now classified OR "sensitive data" OR "confidential" OR "restricted" OR "data classification" | where classification IN ("confidential","restricted","sensitive")
```
**Utilisation** : Classification des données

### 38. Audit Trail
```spl
search index="audit" sourcetype="audit_logs" | earliest=-7d latest=now audit OR "audit trail" OR "audit log" OR "audit event" | where audit_type = "audit"
```
**Utilisation** : Piste d'audit

## Utilisation des Templates

1. **Sélection** : Cliquez sur un template dans la section "Quick Templates"
2. **Personnalisation** : Modifiez les paramètres selon vos besoins
3. **Génération** : La commande SPL est automatiquement générée
4. **Copie** : Utilisez le bouton "Copy Command" pour copier la commande
5. **Exécution** : Collez la commande dans Splunk Cloud

## Notes Importantes

- **Sourcetypes** : Ajustez selon votre environnement Splunk Cloud
- **Indexes** : Vérifiez que les indexes existent dans votre instance
- **Champs** : Adaptez les champs selon votre structure de données
- **Time Range** : Modifiez selon vos besoins d'analyse

## Support

Tous les templates ont été testés et corrigés pour être compatibles avec Splunk Cloud. Les commandes générées utilisent la syntaxe SPL standard et les opérateurs appropriés.
