/* ============================================================================
   ThreatNexus BD — actor corpus
   Nation-state, hacktivist and criminal actors with demonstrated or assessed
   relevance to Bangladesh. Compiled from public government, CERT and vendor
   reporting. Every dossier cites its sources. TLP:CLEAR.

   bd_relevance : 0-100 analyst-assigned exposure score for Bangladesh
   bd_status    : confirmed | assessed | regional | outbound
   ttps         : [ATT&CK id, technique name, tactic]
   ========================================================================== */

export const GROUPS = [

  /* ------------------------------------------------------------------ DPRK */
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    apt: 'APT38 nexus · HIDDEN COBRA',
    aka: 'HIDDEN COBRA · Diamond Sleet · ZINC · Labyrinth Chollima',
    country: 'North Korea',
    agency: 'Reconnaissance General Bureau (RGB), assessed',
    motivation: 'financial',
    confidence: 'high',
    active_since: 2009,
    last_seen: 2026,
    bd_relevance: 96,
    bd_status: 'confirmed',
    sectors: ['Banking & Finance', 'Central Bank / SWIFT', 'Cryptocurrency', 'Defence'],
    bd_targets: ['Bangladesh Bank', 'Commercial banks', 'SWIFT Alliance Access operators', 'Payment intermediaries'],
    targets: ['Bangladesh', 'Philippines', 'Sri Lanka', 'USA', 'South Korea', 'Global'],
    mitre_group: 'G0032',
    description: 'The single most consequential threat actor in Bangladesh\'s cyber history. Between 4–5 February 2016 operators inside Bangladesh Bank\'s SWIFT-connected environment issued 35 fraudulent payment instructions against the bank\'s account at the Federal Reserve Bank of New York, attempting to move roughly US$951m. Five instructions cleared: US$81m to accounts in the Philippines and US$20m to Sri Lanka (recovered); the remaining ~US$850m was blocked after a misspelling in one instruction triggered review. Custom DRIDEX-derived malware interacted with SWIFT Alliance Access, tampered with the local message database and interfered with confirmation printing to delay detection across a weekend. Forensics indicate malware was resident from January 2016, with reconnaissance of staff and procedures preceding it. Bangladesh\'s national CERT (BGD e-GOV CIRT) was itself created in 2016 in the aftermath. The DOJ\'s Park Jin Hyok complaint names the heist as part of the DPRK campaign; only ~US$15m of the Philippine tranche had been recovered as of 2025. BGD e-GOV CIRT still lists Lazarus infrastructure among the APT clusters active against Bangladeshi networks in its 2026 holiday alerts.',
    ttps: [
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1078', 'Valid Accounts', 'initial-access'],
      ['T1059.003', 'Windows Command Shell', 'execution'],
      ['T1543.003', 'Windows Service', 'persistence'],
      ['T1055', 'Process Injection', 'defense-evasion'],
      ['T1070.004', 'File Deletion', 'defense-evasion'],
      ['T1485', 'Data Destruction', 'impact'],
      ['T1565.001', 'Stored Data Manipulation', 'impact'],
      ['T1005', 'Data from Local System', 'collection'],
      ['T1571', 'Non-Standard Port', 'command-and-control'],
      ['T1573.001', 'Symmetric Cryptography', 'command-and-control'],
      ['T1657', 'Financial Theft', 'impact']
    ],
    malware: [
      ['SWIFT-DRIDEX implant', 'Bespoke DRIDEX-derived module reading/altering SWIFT Alliance Access journal and database records'],
      ['NestEgg', 'Backdoor used for persistence and lateral movement (per US v. Park)'],
      ['Macktruck', 'Loader / lateral movement tooling'],
      ['Secure file wiper', 'Anti-forensic module that erased traces post-transfer'],
      ['FakeTLS network stack', 'Custom protocol imitating TLS handshakes to blend C2 traffic']
    ],
    cves: [],
    infra: ['DDNS accounts later linked to DPRK operators', 'FakeTLS C2 over HTTP REST', 'Compromised third-party hosts in the region'],
    campaigns: [
      { name: 'Bangladesh Bank SWIFT heist', date: '2016-02', summary: '35 fraudulent SWIFT instructions; US$101m moved, US$81m lost to Manila casinos.', source: 'BAE Systems / Reuters / US DOJ' },
      { name: 'Sonali Bank (retrospective link)', date: '2013', summary: 'US$250,000 removed via fraudulent SWIFT transfers; re-examined after 2016 and treated as a possible precursor.', source: 'Bangladesh Police / press reporting' },
      { name: 'Continued regional financial targeting', date: '2024-2026', summary: 'DPRK financial tradecraft persists against South Asian banks, crypto exchanges and IT worker supply chains.', source: 'BGD e-GOV CIRT cluster reporting' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'SWIFT / payment host anomalous service creation', query: 'DeviceEvents\n| where ActionType == "ServiceInstalled"\n| where DeviceName has_any ("SWIFT","ALLIANCE","PAY","TREAS")\n| where InitiatingProcessAccountName !in ("SYSTEM_ADMIN_SVC")\n| project Timestamp, DeviceName, InitiatingProcessAccountName, AdditionalFields' },
      { platform: 'SPL', title: 'Off-hours access to payment initiation hosts', query: 'index=wineventlog EventCode=4624 host IN (swift*, pay*, treasury*)\n| eval hr=strftime(_time,"%H")\n| where hr>=18 OR hr<=6\n| stats count by host, Account_Name, hr' }
    ],
    sources: [
      { name: 'Wikipedia — Bangladesh Bank robbery (incident record)', url: 'https://en.wikipedia.org/wiki/Bangladesh_Bank_robbery' },
      { name: 'BAE Systems — "Two bytes to $951m"', url: 'https://baesystemsai.blogspot.com/2016/04/two-bytes-to-951m.html' },
      { name: 'US DOJ — criminal complaint, Park Jin Hyok', url: 'https://www.justice.gov/opa/press-release/file/1092091/download' },
      { name: 'BGD e-GOV CIRT — holiday threat alert (APT clusters incl. Lazarus)', url: 'https://www.cirt.gov.bd/alerts/security-during-long-holiday-march-26' }
    ]
  },

  {
    id: 'apt38',
    name: 'APT38 / BlueNoroff',
    apt: 'APT38',
    aka: 'BlueNoroff · Stardust Chollima · Sapphire Sleet · CageyChameleon',
    country: 'North Korea',
    agency: 'RGB financial-operations cluster, assessed',
    motivation: 'financial',
    confidence: 'high',
    active_since: 2014,
    last_seen: 2026,
    bd_relevance: 78,
    bd_status: 'assessed',
    sectors: ['Banking & Finance', 'Cryptocurrency', 'Payment Switches', 'ATM networks'],
    bd_targets: ['Commercial banks', 'Card/ATM switch operators', 'Mobile financial services', 'Crypto brokerages'],
    targets: ['Bangladesh', 'Vietnam', 'Taiwan', 'Mexico', 'India', 'Global'],
    mitre_group: 'G0082',
    description: 'The financially-focused DPRK cluster that industry reporting places behind SWIFT endpoint compromises, ATM cash-out (FASTCash) and crypto theft. Mandiant\'s "APT38: Un-usual Suspects" describes exactly the mission set executed against Bangladesh Bank, and the group is the template for the risk facing Bangladesh\'s 60+ scheduled banks, its card switches and its fast-growing mobile financial services sector. Tradecraft is patient: months of reconnaissance inside payment environments, study of operator behaviour and reconciliation timing, then a single high-value transfer window aligned to local holidays and weekends — a pattern that maps directly onto Bangladesh\'s Thursday–Friday banking weekend and long Eid closures, which BGD e-GOV CIRT explicitly warns about.',
    ttps: [
      ['T1566.002', 'Spearphishing Link', 'initial-access'],
      ['T1195.002', 'Compromise Software Supply Chain', 'initial-access'],
      ['T1021.002', 'SMB/Windows Admin Shares', 'lateral-movement'],
      ['T1003.001', 'LSASS Memory', 'credential-access'],
      ['T1112', 'Modify Registry', 'defense-evasion'],
      ['T1489', 'Service Stop', 'impact'],
      ['T1657', 'Financial Theft', 'impact'],
      ['T1486', 'Data Encrypted for Impact', 'impact']
    ],
    malware: [
      ['FASTCash', 'AIX/Linux payment-switch implant authorising fraudulent ATM withdrawals'],
      ['DYEPACK', 'SWIFT message manipulation framework'],
      ['CLEANTOAD / KILLSUIT', 'Anti-forensics and log wiping'],
      ['SnatchCrypto toolset', 'Crypto-theft chain against exchanges and startups']
    ],
    cves: [],
    infra: ['Compromised regional hosting for staging', 'Long-lived credential reuse inside payment segments'],
    campaigns: [
      { name: 'FASTCash ATM cash-out (regional risk)', date: '2018-2026', summary: 'Payment-switch implants enabling coordinated ATM withdrawals — a live risk model for South Asian card switches.', source: 'CISA AA18-275A / AA20-239A' }
    ],
    iocs: [],
    hunt: [
      { platform: 'SPL', title: 'Payment switch — unexpected process on AIX/Linux switch host', query: 'index=os sourcetype=linux_audit host IN (switch*, atm*, card*)\n| search exec_path!="/opt/switch/*" exec_path!="/usr/sbin/*"\n| stats count by host, exec_path, user' }
    ],
    sources: [
      { name: 'Mandiant — APT38: Un-usual Suspects', url: 'https://www.mandiant.com/resources/reports/apt38-un-usual-suspects' },
      { name: 'CISA — FASTCash advisories', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-239a' }
    ]
  },

  /* ----------------------------------------------------------- India-nexus */
  {
    id: 'bitter',
    name: 'Bitter',
    apt: 'APT-C-08 · T-APT-17',
    aka: 'APT-C-08 · T-APT-17 · Orange Yali · Hazy Tiger',
    country: 'India',
    agency: 'South Asian state-aligned, assessed',
    motivation: 'espionage',
    confidence: 'high',
    active_since: 2013,
    last_seen: 2026,
    bd_relevance: 92,
    bd_status: 'confirmed',
    sectors: ['Government', 'Military & Defence', 'Law Enforcement', 'Energy', 'Engineering'],
    bd_targets: ['Rapid Action Battalion (RAB)', 'Bangladesh Police', 'Elite government units', 'Military entities'],
    targets: ['Bangladesh', 'Pakistan', 'China', 'Saudi Arabia'],
    mitre_group: 'G1002',
    description: 'Cisco Talos publicly added Bangladesh to Bitter\'s target set in May 2022, documenting a campaign running since August 2021 against an elite Bangladeshi government entity — spear-phishing aimed at high-ranking officers of the Rapid Action Battalion (RAB), delivered as weaponised RTF and Excel documents abusing Equation Editor (CVE-2017-11882). The payload, ZxxZ (Qi-Anxin: MuuyDownloader), is a Visual C++ second-stage trojan masquerading as a Windows Security update service, enumerating installed AV before pulling follow-on tooling. SECUINFRA\'s July 2022 follow-up ("Whatever floats your Boat") showed sustained targeting of Bangladeshi military entities, a switch of the ZxxZ C2 separator to an underscore, and the addition of the .NET Almond RAT. Talos attributed with moderate confidence on C2 infrastructure overlap. Bitter remains on BGD e-GOV CIRT\'s list of APT infrastructure clusters observed against Bangladeshi networks in 2026.',
    ttps: [
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1203', 'Exploitation for Client Execution', 'execution'],
      ['T1204.002', 'Malicious File', 'execution'],
      ['T1053.005', 'Scheduled Task', 'persistence'],
      ['T1036.005', 'Match Legitimate Name or Location', 'defense-evasion'],
      ['T1027', 'Obfuscated Files or Information', 'defense-evasion'],
      ['T1518.001', 'Security Software Discovery', 'discovery'],
      ['T1082', 'System Information Discovery', 'discovery'],
      ['T1105', 'Ingress Tool Transfer', 'command-and-control'],
      ['T1041', 'Exfiltration Over C2 Channel', 'exfiltration']
    ],
    malware: [
      ['ZxxZ / MuuyDownloader', 'VC++ downloader posing as "Windows Security update"; AV enumeration then stage-2 retrieval'],
      ['Almond RAT', '.NET RAT with string encryption; basic collection plus arbitrary command execution'],
      ['BitterRAT', 'Long-running Windows RAT family'],
      ['ArtraDownloader', 'Staged downloader used across South Asian campaigns'],
      ['AndroRAT variants', 'Android surveillance-ware against mobile targets']
    ],
    cves: ['CVE-2017-11882', 'CVE-2018-0798', 'CVE-2017-0199'],
    infra: ['Zimbra and JavaMail senders for phishing delivery', 'C2 overlap with historic Bitter infrastructure', 'Scheduled-task persistence configured from embedded OLE objects'],
    campaigns: [
      { name: 'Bitter adds Bangladesh to their targets', date: '2021-08 → 2022-05', summary: 'Spear-phishing of RAB officers; ZxxZ trojan deployed via Equation Editor exploit.', source: 'Cisco Talos' },
      { name: 'Whatever floats your Boat', date: '2022-07', summary: 'Continued targeting of Bangladeshi military entities; Almond RAT added.', source: 'SECUINFRA' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'Equation Editor spawning child process (CVE-2017-11882)', query: 'DeviceProcessEvents\n| where InitiatingProcessFileName =~ "EQNEDT32.EXE"\n| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName' },
      { platform: 'KQL', title: 'Scheduled task created by Office process', query: 'DeviceProcessEvents\n| where FileName =~ "schtasks.exe"\n| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","eqnedt32.exe")\n| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName' }
    ],
    sources: [
      { name: 'Cisco Talos — Bitter APT adds Bangladesh to their targets', url: 'https://blog.talosintelligence.com/bitter-apt-adds-bangladesh-to-their/' },
      { name: 'The Hacker News — Bitter continues to target Bangladesh military', url: 'https://thehackernews.com/2022/07/bitter-apt-hackers-continue-to-target.html' },
      { name: 'SECUINFRA — Whatever floats your Boat', url: 'https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh/' }
    ]
  },

  {
    id: 'sidewinder',
    name: 'SideWinder',
    apt: 'T-APT-04 · APT-C-17',
    aka: 'Rattlesnake · Razor Tiger · Hardcore Nationalist · BabyElephant',
    country: 'India',
    agency: 'South Asian state-aligned, assessed',
    motivation: 'espionage',
    confidence: 'high',
    active_since: 2012,
    last_seen: 2026,
    bd_relevance: 95,
    bd_status: 'confirmed',
    sectors: ['Military & Defence', 'Government', 'Maritime & Ports', 'Diplomatic', 'Banking & Finance', 'Energy'],
    bd_targets: ['Directorate General of Defence Purchase (DGDP)', 'Bangladesh Air Force', 'DGFI', 'National Webmail Portal (gov.bd)', 'Bangladesh Navy / maritime bodies'],
    targets: ['Bangladesh', 'Pakistan', 'Nepal', 'Sri Lanka', 'Myanmar', 'Maldives', 'Turkey'],
    mitre_group: 'G0121',
    description: 'The most operationally persistent espionage threat to Bangladeshi defence and government email today. Through 2025–2026 SideWinder ran large-scale credential harvesting against Bangladesh: fake Zimbra webmail and "secured file" portals spoofing the Directorate General of Defence Purchase (DGDP), the Bangladesh Air Force, military intelligence (DGFI) and the National Webmail Portal serving the whole of government, hosted on free platforms (Netlify, pages.dev, workers.dev, b4a.run) and funnelling credentials to centralised collectors such as mailbox3-inbox1-bd[.]com. Hunt.io\'s Operation SouthNet tracked 50+ domains across Bangladesh, Nepal, Pakistan, Sri Lanka and Myanmar, with one DGDP lure still live at the end of September 2025. In parallel the group runs a document chain: DOCX remote-template injection → RTF exploiting CVE-2017-11882 → JavaScript loader (aborts if RAM < 950MB) → "Backdoor Loader" side-loaded via signed binaries → StealerBot post-exploitation implant. BGD e-GOV CIRT issued Bangladesh-specific SideWinder advisories in July 2026 (dual-format weaponised documents) and September 2026 (toolkit with GeoServer, Laravel Ignition, Tomcat Manager and Redis exploitation against South Asian government and financial infrastructure).',
    ttps: [
      ['T1566.002', 'Spearphishing Link', 'initial-access'],
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1221', 'Template Injection', 'defense-evasion'],
      ['T1203', 'Exploitation for Client Execution', 'execution'],
      ['T1059.007', 'JavaScript', 'execution'],
      ['T1574.002', 'DLL Side-Loading', 'defense-evasion'],
      ['T1027.007', 'Dynamic API Resolution', 'defense-evasion'],
      ['T1497.001', 'System Checks (anti-sandbox)', 'defense-evasion'],
      ['T1056.001', 'Keylogging', 'collection'],
      ['T1583.001', 'Acquire Infrastructure: Domains', 'resource-development'],
      ['T1583.006', 'Web Services', 'resource-development'],
      ['T1598.003', 'Spearphishing Link (credential harvest)', 'reconnaissance'],
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1041', 'Exfiltration Over C2 Channel', 'exfiltration']
    ],
    malware: [
      ['StealerBot', 'Exclusive modular post-exploitation implant (keylog, screenshot, credential and file theft)'],
      ['Backdoor Loader', 'Side-loaded DLL (JetCfg.dll, policymanager.dll, winmm.dll, xmllite.dll, UxTheme.dll) with control-flow flattening'],
      ['Phishing kits', 'Template-based Zimbra / "Secured File System" portals reusing POST handlers /2135.php and /idef.php']
    ],
    cves: ['CVE-2017-11882', 'CVE-2017-0199', 'CVE-2020-0674'],
    infra: [
      'Netlify / pages.dev / workers.dev / b4a.run staging',
      'Credential collectors: mailbox3-inbox1-bd[.]com, mailbox-inbox-bd[.]com',
      'Legacy domain reuse (updatemaster[.]info)',
      'Open directories staging follow-on payloads'
    ],
    campaigns: [
      { name: 'DGDP / BAF / DGFI credential harvesting', date: '2025-08 → 2025-10', summary: '14+ phishing pages on free hosting spoofing Bangladeshi defence portals; centralised credential collection.', source: 'Hunt.io' },
      { name: 'Operation SouthNet', date: '2025-09', summary: '50+ domains, maritime and port-themed lures across five South Asian states; Bangladesh among core targets.', source: 'Hunt.io' },
      { name: 'Dual-format weaponised documents vs Bangladesh', date: '2026-07-30', summary: 'National CERT advisory on SideWinder spear-phishing using dual-format documents against Bangladeshi entities.', source: 'BGD e-GOV CIRT' },
      { name: 'Government & financial infrastructure toolkit', date: '2026-09-17', summary: 'Recovered toolkit with GeoServer/GeoTools, Laravel Ignition, Tomcat Manager, Redis exploitation and weak-credential attacks.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [
      ['domain', 'mailbox3-inbox1-bd[.]com', 'Credential exfiltration endpoint (public IOC, Hunt.io)'],
      ['domain', 'mailbox-inbox-bd[.]com', 'Alternate credential collector (public IOC, Hunt.io)'],
      ['domain', 'drive-dgdp-gov-bd-files[.]netlify[.]app', 'Fake DGDP "Secured File" portal'],
      ['ipv4', '146.70.118.226', 'Hosting linked to the phishing cluster']
    ],
    hunt: [
      { platform: 'KQL', title: 'Credential POST to non-gov.bd lookalike hosts', query: 'let bad = dynamic(["mailbox3-inbox1-bd.com","mailbox-inbox-bd.com","drive-dgdp-gov-bd-files.netlify.app"]);\nDeviceNetworkEvents\n| where RemoteUrl has_any (bad) or RemoteIP == "146.70.118.226"\n| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName' },
      { platform: 'KQL', title: 'gov.bd lookalike domains on free hosting', query: 'DeviceNetworkEvents\n| where RemoteUrl matches regex @"(?i)(gov-bd|gov\\\\.bd[-.])" and RemoteUrl has_any ("netlify.app","pages.dev","workers.dev","b4a.run")\n| summarize hits=count() by DeviceName, RemoteUrl' },
      { platform: 'SPL', title: 'Office remote template injection egress', query: 'index=proxy (user_agent="Microsoft Office*" OR process="WINWORD.EXE")\n| search url="*.dotm" OR url="*.rtf"\n| stats count by src_ip, url, user' }
    ],
    sources: [
      { name: 'Hunt.io — Operation SouthNet: SideWinder in South Asia', url: 'https://hunt.io/blog/operation-southnet-sidewinder-south-asia-maritime-phishing' },
      { name: 'GBHackers — SideWinder impersonates BD government & military portals', url: 'https://gbhackers.com/apt-sidewinder-impersonates-government-and-military-agencies/' },
      { name: 'BGD e-GOV CIRT — SideWinder-associated campaign advisory', url: 'https://www.cirt.gov.bd/advisories/sidewinder-associated-campaign' },
      { name: 'Kaspersky Securelist — SideWinder 2024 toolset update', url: 'https://securelist.com/sidewinder-apt-updates-its-toolset/' }
    ]
  },

  {
    id: 'donot',
    name: 'DoNot Team',
    apt: 'APT-C-35',
    aka: 'Origami Elephant · Mint Tempest · SECTOR02 · Viceroy Tiger',
    country: 'India',
    agency: 'India-aligned, assessed',
    motivation: 'espionage',
    confidence: 'high',
    active_since: 2016,
    last_seen: 2026,
    bd_relevance: 94,
    bd_status: 'confirmed',
    sectors: ['Military & Defence', 'Government', 'Diplomatic', 'NGO'],
    bd_targets: ['Bangladesh Air Force officers', 'Defence establishment', 'Diplomatic missions', 'Military-adjacent personnel'],
    targets: ['Bangladesh', 'Pakistan', 'Sri Lanka', 'Nepal', 'Italy', 'EU'],
    mitre_group: 'G0130',
    description: 'DoNot runs the most precisely tailored operation against Bangladeshi defence personnel currently documented. Cyderes\' Howler Cell published an intrusion in July 2026 built around a weaponised RTF named "Biography Air Vice Marshal Sitwat Nayeem.doc": remote template injection pulls a VBA macro, with server-side geofencing that only delivers the payload to victims inside the target region. The final stage is a DLL implant persisted as a scheduled task disguised as OneDrive telemetry (rundll32 %TEMP%\\BinSat\\dn110mploc.dll,a4Strau), profiling CPU, OS, hostname and installed software before beaconing to a secondary C2 over HTTPS with AES-128-CBC in a two-phase handshake that gates payload delivery on the host profile. Attribution is high-confidence on four independent lines: identical C2 URI paths, byte-for-byte AES key material matching documented DoNot samples, VBA staging tradecraft and a linked domain cluster. BGD e-GOV CIRT issued a national advisory on the campaign on 17 August 2026. The group also uses Bangladesh as a *lure theme* abroad — Trellix documented a 2025 operation against a Southern European foreign ministry using the subject "Italian Defence Attaché Visit to Dhaka, Bangladesh" — and runs Android surveillance-ware (Tanzeem) distributed through OneSignal push notifications.',
    ttps: [
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1221', 'Template Injection', 'defense-evasion'],
      ['T1204.002', 'Malicious File', 'execution'],
      ['T1059.005', 'Visual Basic', 'execution'],
      ['T1218.011', 'Rundll32', 'defense-evasion'],
      ['T1053.005', 'Scheduled Task', 'persistence'],
      ['T1027', 'Obfuscated Files or Information', 'defense-evasion'],
      ['T1082', 'System Information Discovery', 'discovery'],
      ['T1518', 'Software Discovery', 'discovery'],
      ['T1573.001', 'Symmetric Cryptography (AES-128-CBC)', 'command-and-control'],
      ['T1071.001', 'Web Protocols', 'command-and-control'],
      ['T1636.003', 'Protected User Data: SMS (Android)', 'collection']
    ],
    malware: [
      ['dn110mploc.dll / BinSat implant', 'Modular DLL implant; scheduled-task persistence masquerading as OneDrive telemetry'],
      ['ejtest.dll', 'Live second-stage module pulled from active infrastructure during analysis'],
      ['Tanzeem / Tanzeem Update', 'Android surveillance-ware harvesting SMS, calls, contacts, location, screenshots'],
      ['YTY / Jaca framework', 'Long-running DoNot modular espionage framework']
    ],
    cves: ['CVE-2017-11882'],
    infra: [
      'Server-side geofencing restricting payload delivery to the target region',
      'C2 parameters mopd= and malp= in URI paths',
      'Google Drive-hosted RAR archives for diplomatic lures',
      'OneSignal push platform abused for phishing delivery (first observed APT use)'
    ],
    campaigns: [
      { name: 'Biography lure vs Bangladesh Air Force', date: '2026-07', summary: 'Geofenced RTF → VBA → shellcode loaders → AES-encrypted DLL implant against BD military/defence personnel.', source: 'Cyderes Howler Cell' },
      { name: 'BGD e-GOV CIRT national advisory', date: '2026-08-17', summary: 'CERT advisory confirming DoNot espionage campaign against Bangladesh military and defence personnel.', source: 'BGD e-GOV CIRT' },
      { name: 'Dhaka-themed lure vs EU ministry', date: '2025-07', summary: '"Italian Defence Attaché Visit to Dhaka, Bangladesh" phishing against a Southern European foreign ministry.', source: 'Trellix' },
      { name: 'Tanzeem Android campaign', date: '2024-10 → 2025-01', summary: 'Android malware via OneSignal notifications against South Asian government and military targets.', source: 'CYFIRMA / ThaiCERT' }
    ],
    iocs: [
      ['file', 'Biography Air Vice Marshal Sitwat Nayeem.doc', 'Weaponised RTF lure (public IOC)'],
      ['path', '%TEMP%\\BinSat\\dn110mploc.dll', 'Implant path executed via rundll32 export a4Strau'],
      ['email', 'int[.]dte[.]afd[.]1@gmail[.]com', 'Sender used in the Dhaka-themed diplomatic lure']
    ],
    hunt: [
      { platform: 'KQL', title: 'rundll32 executing DLL from %TEMP% subfolder', query: 'DeviceProcessEvents\n| where FileName =~ "rundll32.exe"\n| where ProcessCommandLine has @"\\AppData\\Local\\Temp\\" and ProcessCommandLine has ".dll,"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName' },
      { platform: 'KQL', title: 'Scheduled task masquerading as OneDrive telemetry', query: 'DeviceProcessEvents\n| where ProcessCommandLine has "schtasks" and ProcessCommandLine has_any ("OneDrive","Telemetry")\n| where ProcessCommandLine has "rundll32"\n| project Timestamp, DeviceName, ProcessCommandLine' },
      { platform: 'Sigma', title: 'RTF opening → outbound template fetch', query: 'detection:\n  selection:\n    Image|endswith: "\\WINWORD.EXE"\n    CommandLine|contains: ".rtf"\n  network:\n    Initiated: true\n    DestinationPort: [80, 443]\n  condition: selection and network' }
    ],
    sources: [
      { name: 'Cyderes Howler Cell — DoNot intrusion vs Bangladesh military', url: 'https://www.cyderes.com/howler-cell/tracking-donot-apt-c-35-bangladesh-military-intrusion' },
      { name: 'BGD e-GOV CIRT — DoNot (APT-C-35) advisory', url: 'https://www.cirt.gov.bd/advisories/donot-apt-c-35' },
      { name: 'Trellix — DoNot vs Southern European government (Dhaka lure)', url: 'https://www.trellix.com/blogs/research/from-click-to-compromise-unveiling-the-sophisticated-attack-of-donot-apt-group-on-southern-european-government-entities/' },
      { name: 'ThaiCERT / CYFIRMA — Tanzeem Android malware', url: 'https://www.thaicert.or.th/en/2025/01/22/the-apt-group-donot-team-uses-the-tanzeem-malware-to-attack-organizations-in-south-asia/' }
    ]
  },

  {
    id: 'confucius',
    name: 'Confucius',
    apt: 'APT-C-?? (South Asia)',
    aka: 'Confucius APT · Sneaky Elephant (overlaps)',
    country: 'India',
    agency: 'South Asian state-aligned, assessed',
    motivation: 'espionage',
    confidence: 'moderate',
    active_since: 2013,
    last_seen: 2025,
    bd_relevance: 55,
    bd_status: 'regional',
    sectors: ['Government', 'Military & Defence', 'Diplomatic', 'Education'],
    bd_targets: ['Regional government targets', 'Diplomatic and policy community'],
    targets: ['Pakistan', 'Bangladesh', 'Sri Lanka', 'Nepal', 'China'],
    description: 'A long-running South Asian espionage cluster with tradecraft and target overlap with Bitter and SideWinder — document lures, Office exploits, custom downloaders and Android surveillance-ware against South Asian government, military and policy targets. Bangladesh sits inside its regional aperture rather than being a documented primary target, so it is tracked here at regional-relevance level: the value is alias hygiene (avoid mis-attributing Bitter/SideWinder activity) and shared-infrastructure pivoting.',
    ttps: [
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1203', 'Exploitation for Client Execution', 'execution'],
      ['T1105', 'Ingress Tool Transfer', 'command-and-control'],
      ['T1005', 'Data from Local System', 'collection'],
      ['T1074.001', 'Local Data Staging', 'collection']
    ],
    malware: [['Hornbill / SunBird', 'Android surveillance families associated with the cluster'], ['WarzoneRAT (commodity)', 'Off-the-shelf RAT used in later campaigns']],
    cves: ['CVE-2017-11882', 'CVE-2015-1641'],
    infra: ['Shared hosting overlapping other South Asian clusters'],
    campaigns: [],
    iocs: [],
    hunt: [],
    sources: [{ name: 'MITRE ATT&CK / vendor reporting on South Asian clusters', url: 'https://attack.mitre.org/groups/' }]
  },

  /* -------------------------------------------------------- Pakistan-nexus */
  {
    id: 'sidecopy',
    name: 'SideCopy',
    apt: 'SideCopy',
    aka: 'APT36 sub-cluster (assessed) · Transparent Tribe affiliate',
    country: 'Pakistan',
    agency: 'Pakistan-aligned, assessed',
    motivation: 'espionage',
    confidence: 'moderate',
    active_since: 2019,
    last_seen: 2026,
    bd_relevance: 72,
    bd_status: 'assessed',
    sectors: ['Government', 'Military & Defence', 'Diplomatic'],
    bd_targets: ['Government users receiving South Asia-themed lures', 'Defence-adjacent organisations'],
    targets: ['India', 'Afghanistan', 'Bangladesh', 'South Asia'],
    description: 'SideCopy imitates SideWinder\'s infection chains (hence the name) while pursuing Pakistan-aligned collection. BGD e-GOV CIRT issued a Bangladesh advisory on 23 September 2026 covering a SideCopy campaign using spear-phishing with weaponised Windows shortcut (.LNK) files, mshta.exe execution and multi-stage fileless RAT deployment — a chain that defeats file-based AV and needs process-lineage and script-block telemetry to catch. The group recycles commodity and leaked RATs (AllaKore, Ares, ReverseRAT, Action RAT) which raises the false-attribution risk for defenders in Dhaka: the same tooling appears in unrelated criminal intrusions.',
    ttps: [
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1204.001', 'Malicious Link', 'execution'],
      ['T1218.005', 'Mshta', 'defense-evasion'],
      ['T1059.001', 'PowerShell', 'execution'],
      ['T1547.001', 'Registry Run Keys / Startup Folder', 'persistence'],
      ['T1620', 'Reflective Code Loading', 'defense-evasion'],
      ['T1105', 'Ingress Tool Transfer', 'command-and-control'],
      ['T1113', 'Screen Capture', 'collection']
    ],
    malware: [
      ['ReverseRAT', 'Custom .NET RAT used across SideCopy operations'],
      ['Action RAT', 'Delphi RAT with command execution and exfiltration'],
      ['AllaKore RAT (modified)', 'Repurposed open-source RAT'],
      ['Fileless loaders', 'HTA/JS chains staging payloads entirely in memory']
    ],
    cves: ['CVE-2023-38831'],
    infra: ['.LNK + mshta.exe delivery', 'HTA staging servers', 'Compromised legitimate sites for hosting'],
    campaigns: [
      { name: 'MSHTA / weaponised LNK fileless RAT campaign', date: '2026-09-23', summary: 'National CERT advisory: spear-phishing with .LNK files, mshta.exe, multi-stage fileless RAT execution.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'mshta.exe launched from Explorer / LNK', query: 'DeviceProcessEvents\n| where FileName =~ "mshta.exe"\n| where InitiatingProcessFileName in~ ("explorer.exe","cmd.exe","wscript.exe")\n| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName' },
      { platform: 'SPL', title: 'LNK execution followed by outbound HTA fetch', query: 'index=edr process_name IN (mshta.exe, powershell.exe) parent_process_name=explorer.exe\n| transaction host maxspan=2m\n| search url="*.hta"' }
    ],
    sources: [
      { name: 'BGD e-GOV CIRT — SideCopy campaign advisory (Sep 2026)', url: 'https://www.cirt.gov.bd/advisories/sidecopy-campaign-sep-26' },
      { name: 'Seqrite / Cisco Talos — SideCopy tooling analyses', url: 'https://blog.talosintelligence.com/transparent-tribe-targets-education/' }
    ]
  },

  {
    id: 'apt36',
    name: 'Transparent Tribe',
    apt: 'APT36',
    aka: 'Mythic Leopard · ProjectM · Earth Karkaddan',
    country: 'Pakistan',
    agency: 'Pakistan-aligned, assessed',
    motivation: 'espionage',
    confidence: 'moderate',
    active_since: 2013,
    last_seen: 2026,
    bd_relevance: 58,
    bd_status: 'regional',
    sectors: ['Government', 'Military & Defence', 'Education', 'Diplomatic'],
    bd_targets: ['Regional government and defence targets', 'Linux desktop users in government (BOSS-style distros)'],
    targets: ['India', 'Afghanistan', 'Bangladesh', 'South Asia'],
    mitre_group: 'G0134',
    description: 'Primarily an India-focused espionage group, but its malware families are on BGD e-GOV CIRT\'s list of RAT/backdoor clusters observed in Bangladeshi cyberspace (Crimson RAT and Oblique RAT appear by name in the CERT\'s 2026 holiday threat alert). Relevance to Bangladesh is therefore twofold: regional spillover onto shared-service and diplomatic targets, and commodity reuse of its tooling by other operators. Recent tradecraft includes Linux desktop targeting and credential-phishing kits imitating government mail portals — the same pattern Bangladeshi government webmail faces from SideWinder.',
    ttps: [
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1204.002', 'Malicious File', 'execution'],
      ['T1059.005', 'Visual Basic', 'execution'],
      ['T1547.001', 'Registry Run Keys / Startup Folder', 'persistence'],
      ['T1113', 'Screen Capture', 'collection'],
      ['T1056.001', 'Keylogging', 'collection'],
      ['T1041', 'Exfiltration Over C2 Channel', 'exfiltration']
    ],
    malware: [
      ['Crimson RAT', 'Flagship .NET RAT — listed by BGD e-GOV CIRT among RAT clusters seen in Bangladesh'],
      ['Oblique RAT', 'Second RAT family named in the same CERT cluster list'],
      ['CapraRAT', 'Android surveillance-ware in trojanised apps'],
      ['Poseidon (Linux)', 'Golang agent for Linux desktop targets']
    ],
    cves: ['CVE-2017-0199'],
    infra: ['Lookalike government webmail portals', 'Dynamic DNS C2'],
    campaigns: [
      { name: 'Crimson/Oblique RAT activity observed in BD cyberspace', date: '2026-03', summary: 'Named in the national CERT\'s APT/RAT infrastructure cluster list ahead of the Eid holiday period.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'Crimson RAT-style .NET child of Office', query: 'DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe")\n| where FileName endswith ".exe" and FolderPath has_any (@"\\AppData\\", @"\\ProgramData\\")\n| project Timestamp, DeviceName, FolderPath, ProcessCommandLine' }
    ],
    sources: [
      { name: 'BGD e-GOV CIRT — holiday alert listing Crimson/Oblique RAT clusters', url: 'https://www.cirt.gov.bd/alerts/security-during-long-holiday-march-26' },
      { name: 'MITRE ATT&CK — Transparent Tribe (G0134)', url: 'https://attack.mitre.org/groups/G0134/' }
    ]
  },

  /* ------------------------------------------------------------ China-nexus */
  {
    id: 'mustangpanda',
    name: 'Mustang Panda',
    apt: 'TA416',
    aka: 'Earth Preta · Twill Typhoon · Fireant · HoneyMyte · Polaris',
    country: 'China',
    agency: 'PRC state-sponsored, assessed',
    motivation: 'espionage',
    confidence: 'high',
    active_since: 2014,
    last_seen: 2026,
    bd_relevance: 74,
    bd_status: 'regional',
    sectors: ['Government', 'Telecom', 'Diplomatic', 'NGO', 'Maritime & Ports'],
    bd_targets: ['Government ministries', 'Telecom operators', 'Diplomatic missions', 'Belt-and-Road adjacent projects'],
    targets: ['Myanmar', 'Mongolia', 'Malaysia', 'Bangladesh', 'Russia', 'South & Southeast Asia'],
    mitre_group: 'G0129',
    description: 'The most active PRC espionage actor across Bangladesh\'s neighbourhood. Kaspersky documented an updated COOLCLIENT backdoor in 2025–2026 operations against government entities in Myanmar, Mongolia, Malaysia and Russia, deployed alongside PlugX and LuminousMoth, with DLL side-loading through signed binaries from Bitdefender, VLC, Ulead PhotoImpact and Sangfor. Symantec previously tracked a multi-year campaign against multiple telecom operators in a single Asian country. For Bangladesh the exposure is structural rather than (yet) publicly evidenced: government ministries, telecom operators and infrastructure programmes matching Mustang Panda\'s documented collection priorities, plus heavy regional use of USB-borne worming (TONEDISK) that crosses air-gapped and field-office networks common in Bangladeshi administration.',
    ttps: [
      ['T1566.001', 'Spearphishing Attachment', 'initial-access'],
      ['T1091', 'Replication Through Removable Media', 'lateral-movement'],
      ['T1574.002', 'DLL Side-Loading', 'defense-evasion'],
      ['T1055', 'Process Injection', 'defense-evasion'],
      ['T1555.003', 'Credentials from Web Browsers', 'credential-access'],
      ['T1115', 'Clipboard Data', 'collection'],
      ['T1113', 'Screen Capture', 'collection'],
      ['T1567.002', 'Exfiltration to Cloud Storage', 'exfiltration'],
      ['T1071.001', 'Web Protocols', 'command-and-control']
    ],
    malware: [
      ['PlugX', 'Long-running modular backdoor, usually side-loaded'],
      ['COOLCLIENT', 'Updated 2025-2026 secondary backdoor (file ops, clipboard, window monitoring)'],
      ['TONESHELL', 'Persistence and payload-dropping implant'],
      ['TONEDISK', 'USB worm for offline/air-gapped propagation'],
      ['QReverse', 'RAT with remote shell, file management, screenshots'],
      ['Browser stealers', 'Chrome/Edge credential and Firefox cookie theft, exfil via Google Drive']
    ],
    cves: [],
    infra: ['Signed third-party binaries abused for side-loading', 'Cloud storage (Google Drive) exfiltration', 'Long-lived regional VPS C2'],
    campaigns: [
      { name: 'COOLCLIENT government espionage', date: '2025-2026', summary: 'Updated backdoor against government targets in Myanmar, Mongolia, Malaysia and Russia.', source: 'Kaspersky' },
      { name: 'Asian telecom operator campaign', date: '2021-2024', summary: 'Multi-year espionage inside telecom operators of a single Asian country.', source: 'Symantec' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'Signed binary side-loading unsigned DLL from user path', query: 'DeviceImageLoadEvents\n| where FolderPath has_any (@"\\AppData\\", @"\\ProgramData\\", @"\\Users\\Public\\")\n| where InitiatingProcessFileName in~ ("vlc.exe","googleupdate.exe","olreg.exe","sang.exe","qutppy.exe")\n| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath' },
      { platform: 'KQL', title: 'USB-borne executable launch (TONEDISK pattern)', query: 'DeviceProcessEvents\n| where FolderPath startswith "E:\\\\" or FolderPath startswith "F:\\\\"\n| where FileName endswith ".exe"\n| summarize count() by DeviceName, FolderPath, FileName' }
    ],
    sources: [
      { name: 'The Hacker News — Mustang Panda COOLCLIENT (Jan 2026)', url: 'https://thehackernews.com/2026/01/mustang-panda-deploys-updated.html' },
      { name: 'MITRE ATT&CK — Mustang Panda (G0129)', url: 'https://attack.mitre.org/groups/G0129/' }
    ]
  },

  {
    id: 'salttyphoon',
    name: 'Salt Typhoon',
    apt: 'UNC5807',
    aka: 'Earth Estries · GhostEmperor · OPERATOR PANDA · RedMike',
    country: 'China',
    agency: 'Ministry of State Security (MSS), assessed',
    motivation: 'espionage',
    confidence: 'high',
    active_since: 2019,
    last_seen: 2026,
    bd_relevance: 80,
    bd_status: 'assessed',
    sectors: ['Telecom & ISP', 'Government', 'Transportation', 'Military & Defence', 'Hospitality'],
    bd_targets: ['Mobile network operators', 'IIG / ISP backbone routers', 'Submarine-cable landing and transit providers', 'Lawful-intercept adjacent systems'],
    targets: ['USA', 'Canada', 'Europe', 'Indo-Pacific', 'Global (80+ countries reported)'],
    description: 'The defining telecom-espionage actor of the decade, and the clearest structural risk to Bangladesh\'s communications backbone. The August 2025 CISA/NSA/FBI joint advisory (AA25-239A) describes state-sponsored actors exploiting provider-edge and customer-edge backbone routers — devices with poor logging and little EDR coverage — modifying firmware and ACLs, enabling traffic mirroring, tunnelling over non-standard protocols and abusing peering connections for exfiltration. Reporting through 2026 puts the campaign in networks across 80+ countries, including Indo-Pacific providers, and a separate China-linked campaign in February 2026 reportedly touched 50+ telecoms and government agencies across 42 countries. Bangladesh\'s operator market, IIG/NIX topology and ageing edge-router estate present precisely the attack surface described; there is no public confirmation of a Bangladeshi victim, so this is carried as an assessed, not confirmed, exposure.',
    ttps: [
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1133', 'External Remote Services', 'initial-access'],
      ['T1542.004', 'ROMMONkit / firmware modification', 'persistence'],
      ['T1601.001', 'Patch System Image', 'defense-evasion'],
      ['T1562.008', 'Impair Defenses: Disable Logging', 'defense-evasion'],
      ['T1040', 'Network Sniffing', 'credential-access'],
      ['T1020.001', 'Traffic Duplication', 'exfiltration'],
      ['T1572', 'Protocol Tunneling', 'command-and-control'],
      ['T1090.003', 'Multi-hop Proxy', 'command-and-control'],
      ['T1078.003', 'Local Accounts', 'persistence']
    ],
    malware: [['Router implants / custom firmware', 'Persistent access on provider- and customer-edge routers'], ['Demodex rootkit (GhostEmperor)', 'Kernel-level Windows rootkit in historical operations'], ['Open-source pivoting tools', 'Multi-hop proxy chains between provider networks']],
    cves: ['CVE-2023-20198', 'CVE-2023-20273', 'CVE-2018-0171'],
    infra: ['Compromised edge routers used as hop points', 'Modified ACLs and non-standard listening ports', 'Abused peering relationships for exfiltration'],
    campaigns: [
      { name: 'Global telecom backbone campaign', date: '2021-2026', summary: 'Persistent access to telecom, government, transport and lodging networks worldwide via router exploitation.', source: 'CISA AA25-239A' }
    ],
    iocs: [],
    hunt: [
      { platform: 'SPL', title: 'Router config change outside change window', query: 'index=network sourcetype=cisco:ios ("configured from" OR "%SYS-5-CONFIG_I")\n| eval hr=strftime(_time,"%H")\n| where hr<08 OR hr>20\n| stats count by host, user, hr' },
      { platform: 'SPL', title: 'New SPAN / traffic-mirroring session', query: 'index=network ("monitor session" OR "port-mirror" OR "erspan")\n| stats earliest(_time) as first_seen by host, session\n| where first_seen > relative_time(now(), "-30d")' }
    ],
    sources: [
      { name: 'CISA — Joint advisory on PRC state-sponsored actors (AA25-239A)', url: 'https://www.cisa.gov/news-events/alerts/2025/08/27/cisa-and-partners-release-joint-advisory-countering-chinese-state-sponsored-actors-compromise' },
      { name: 'SecurityWeek — Salt Typhoon critical infrastructure campaign', url: 'https://www.securityweek.com/chinas-salt-typhoon-hacked-critical-infrastructure-globally-for-years/' }
    ]
  },

  {
    id: 'apt41',
    name: 'APT41',
    apt: 'APT41',
    aka: 'Winnti · Brass Typhoon · Barium · Wicked Panda',
    country: 'China',
    agency: 'PRC state-sponsored with criminal moonlighting',
    motivation: 'mixed',
    confidence: 'high',
    active_since: 2012,
    last_seen: 2026,
    bd_relevance: 60,
    bd_status: 'regional',
    sectors: ['Government', 'Telecom', 'Healthcare', 'Gaming', 'Software supply chain', 'Logistics'],
    bd_targets: ['Internet-facing enterprise applications', 'Software/IT service providers', 'Telecom and logistics platforms'],
    targets: ['Global', 'South & Southeast Asia'],
    mitre_group: 'G0096',
    description: 'A dual-mission PRC actor: state espionage plus financially motivated intrusion. Its signature is rapid weaponisation of newly disclosed vulnerabilities in internet-facing enterprise software — exactly the class of exposure BGD e-GOV CIRT keeps flagging nationally (452 Bangladeshi IPs running end-of-life Microsoft IIS in March 2026; 80 exposed MongoDB instances; a critical unauthenticated RCE in n8n, CVE-2026-21858). Bangladesh\'s risk from APT41-style actors is less about bespoke targeting and more about being opportunistically swept up in mass exploitation of unpatched edge software, then retained if the victim is interesting.',
    ttps: [
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1505.003', 'Web Shell', 'persistence'],
      ['T1195.002', 'Compromise Software Supply Chain', 'initial-access'],
      ['T1078', 'Valid Accounts', 'persistence'],
      ['T1560.001', 'Archive via Utility', 'collection'],
      ['T1572', 'Protocol Tunneling', 'command-and-control'],
      ['T1486', 'Data Encrypted for Impact', 'impact']
    ],
    malware: [['ShadowPad', 'Modular backdoor — named in BGD e-GOV CIRT cluster reporting for Bangladesh'], ['Cobalt Strike (abused)', 'Commodity C2 also listed by the national CERT'], ['Winnti rootkit', 'Kernel persistence in supply-chain operations']],
    cves: ['CVE-2019-19781', 'CVE-2021-44228', 'CVE-2024-27198'],
    infra: ['Web shells on edge appliances', 'Cloud-hosted staging', 'Legitimate service abuse for C2'],
    campaigns: [
      { name: 'ShadowPad/Cobalt Strike clusters observed in BD', date: '2026-03', summary: 'National CERT lists ShadowPad and Cobalt Strike among espionage infrastructure clusters affecting Bangladesh.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'Web server spawning shell (web shell execution)', query: 'DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","tomcat9.exe")\n| where FileName in~ ("cmd.exe","powershell.exe","bash","sh")\n| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName' }
    ],
    sources: [
      { name: 'BGD e-GOV CIRT — EOL IIS exposure in Bangladesh', url: 'https://www.cirt.gov.bd/advisories/end-of-life-microsoft-iis-servers-in-bangladesh' },
      { name: 'MITRE ATT&CK — APT41 (G0096)', url: 'https://attack.mitre.org/groups/G0096/' }
    ]
  },

  /* ------------------------------------------------------------ Hacktivism */
  {
    id: 'mtb',
    name: 'Mysterious Team Bangladesh',
    apt: 'MTB',
    aka: 'MT Bangladesh · founded by "D4RK TSN"',
    country: 'Bangladesh',
    agency: 'Non-state hacktivist collective',
    motivation: 'hacktivism',
    confidence: 'high',
    active_since: 2020,
    last_seen: 2026,
    bd_relevance: 70,
    bd_status: 'outbound',
    sectors: ['Government', 'Banking & Finance', 'Transportation'],
    bd_targets: ['Bangladesh-origin actor — operates outbound; drives retaliatory targeting of BD assets'],
    direction: 'outbound',
    outbound_targets: [
      ['India', 34, 'Government, financial and transport targets; named by DSCI among 150+ crews striking Indian critical infrastructure'],
      ['Israel', 18, 'Government and media targets during regional escalations'],
      ['Other / unspecified', 48, 'Remaining campaign volume, not broken out in the source reporting']
    ],
    targets: ['India', 'Israel', 'Australia', 'Sweden', 'Netherlands', 'Senegal', 'Ethiopia'],
    description: 'A Bangladesh-origin hacktivist collective founded in 2020 by an actor using the handle "D4RK TSN", which Group-IB credited with 750+ DDoS attacks and 70+ website defacements in a single year, 34% of them against India and 18% against Israel, concentrated on government, financial and transport targets. Tradecraft is low-sophistication but high-tempo: short "test" DDoS bursts to gauge resistance, then full campaigns; opportunistic exploitation of vulnerable phpMyAdmin and WordPress installs and default admin credentials for defacement. It matters to Bangladeshi defenders for the second-order effect: DSCI\'s 2025 threat advisory names MTB among 150+ hacktivist groups striking Indian critical infrastructure, and each outbound wave has been followed by retaliatory defacement and DDoS against Bangladeshi government and bank websites. Listed here as an *outbound* actor — included for completeness of the national picture, not as a target set.',
    ttps: [
      ['T1498.001', 'Direct Network Flood', 'impact'],
      ['T1498.002', 'Reflection Amplification', 'impact'],
      ['T1491.002', 'External Defacement', 'impact'],
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1110.001', 'Password Guessing', 'credential-access'],
      ['T1583.006', 'Web Services (Telegram coordination)', 'resource-development']
    ],
    malware: [['Open-source DDoS utilities', 'Commodity stressers and scripts'], ['Defacement kits', 'Mass-upload scripts against CMS admin panels']],
    cves: [],
    infra: ['Telegram, Facebook and X for coordination and claims', 'Compromised shared hosting for staging'],
    campaigns: [
      { name: 'Anti-India DDoS/defacement wave', date: '2022-06 → 2023-08', summary: '750+ DDoS and 70+ defacements; government, banking and transport targets.', source: 'Group-IB / The Record' },
      { name: 'Named in DSCI hacktivist advisory', date: '2025', summary: 'Listed among 150+ hacktivist groups striking Indian critical infrastructure (4,000+ attacks 2023-2025).', source: 'DSCI threat advisory' }
    ],
    iocs: [],
    hunt: [
      { platform: 'SPL', title: 'Defacement canary — unexpected index.html change', query: 'index=web sourcetype=file_integrity path="*/index.*"\n| stats values(action) by host, path, user\n| where action="modified"' }
    ],
    sources: [
      { name: 'The Record — Bangladeshi hacktivists targeting India and Israel', url: 'https://therecord.media/bangladesh-hacktivistis-targeting-india' },
      { name: 'Group-IB — Mysterious Team Bangladesh research', url: 'https://www.group-ib.com/blog/mysterious-team-bangladesh/' }
    ]
  },

  {
    id: 'regional-hacktivists',
    name: 'Regional Hacktivist Conflict Cluster',
    apt: 'Multiple / unattributed',
    aka: 'India–Bangladesh cyber conflict · religious-nationalist crews',
    country: 'Unknown',
    agency: 'Non-state, loosely coordinated',
    motivation: 'hacktivism',
    confidence: 'moderate',
    active_since: 2021,
    last_seen: 2026,
    bd_relevance: 84,
    bd_status: 'confirmed',
    sectors: ['Government', 'Banking & Finance', 'Healthcare', 'Education', 'Energy', 'Media'],
    bd_targets: ['gov.bd web estate', 'Banks and NBFIs', 'Hospital and university portals', 'State-owned enterprises'],
    direction: 'bidirectional',
    outbound_targets: [
      ['India', 50, 'Bangladeshi crews deface Indian government, university and SME sites in retaliatory waves']
    ],
    targets: ['Bangladesh', 'India'],
    description: 'A persistent tit-for-tat defacement and DDoS conflict between Indian and Bangladeshi crews, fuelled by nationalist and religious sentiment and coordinated largely in Telegram channels. BGD e-GOV CIRT has repeatedly issued date-anchored situational alerts — ahead of 15 August, around national holidays, and a July 2025 alert for CII, energy and banking warning of web application exploitation, defacement, credential compromise and DDoS. Bangladeshi reporting through 2023 documented waves against government sites, a state-owned investment company (100,000+ investor records claimed), and health and education portals. In May 2026 the national CERT attributed web defacement artefacts on Bangladeshi government infrastructure to a global Magento exploitation campaign — a reminder that "hacktivist" claims often ride on mass CMS/e-commerce exploitation rather than targeted intrusion.',
    ttps: [
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1491.002', 'External Defacement', 'impact'],
      ['T1498', 'Network Denial of Service', 'impact'],
      ['T1078', 'Valid Accounts', 'initial-access'],
      ['T1505.003', 'Web Shell', 'persistence'],
      ['T1213.003', 'Code Repositories', 'collection']
    ],
    malware: [['Mass defacement scripts', 'CMS/plugin exploitation at scale'], ['Booter/stresser services', 'Rented DDoS capacity']],
    cves: ['CVE-2024-34102', 'CVE-2022-24086'],
    infra: ['Telegram claim channels and mirrors', 'Shared exploitation of Magento/WordPress/phpMyAdmin'],
    campaigns: [
      { name: 'Situational alert — CII, energy, banks', date: '2025-07-25', summary: 'CERT warning of large-scale attacks on Bangladesh ICT infrastructure: web exploitation, defacement, credential compromise, DDoS.', source: 'BGD e-GOV CIRT' },
      { name: 'Magento-linked defacement of gov infrastructure', date: '2026-05-03', summary: 'Defacement artefacts on Bangladesh government infrastructure tied to global Magento exploitation.', source: 'BGD e-GOV CIRT' },
      { name: '15 August targeting wave', date: '2023-08', summary: 'Anticipated attacks on CII, banks, healthcare and government; defacements and data-leak claims followed.', source: 'BGD e-GOV CIRT / press' }
    ],
    iocs: [],
    hunt: [
      { platform: 'SPL', title: 'Spike in 4xx/5xx and POST to CMS admin paths', query: 'index=web uri_path IN ("/wp-login.php","/administrator/*","/phpmyadmin/*","/admin/*")\n| timechart span=10m count by status' }
    ],
    sources: [
      { name: 'BGD e-GOV CIRT — Situational alert for CII, energy, banks', url: 'https://www.cirt.gov.bd/alerts/cii-energy-banks-2025-07' },
      { name: 'The Daily Star — Hackers feast on government sites', url: 'https://www.thedailystar.net/news/bangladesh/crime-justice/news/hackers-feast-government-sites-3364261' },
      { name: 'BGD e-GOV CIRT — Magento-linked defacement advisory', url: 'https://www.cirt.gov.bd/advisories' }
    ]
  },

  /* ------------------------------------------------------------- Criminal */
  {
    id: 'alphv',
    name: 'ALPHV / BlackCat',
    apt: 'RaaS',
    aka: 'BlackCat · Noberus',
    country: 'Unknown',
    agency: 'Ransomware-as-a-Service (Russian-speaking ecosystem)',
    motivation: 'financial',
    confidence: 'high',
    active_since: 2021,
    last_seen: 2024,
    bd_relevance: 76,
    bd_status: 'confirmed',
    sectors: ['Banking & Finance', 'Government', 'Healthcare', 'Aviation', 'Manufacturing'],
    bd_targets: ['Bangladesh Krishi Bank (2023)', 'State-owned enterprises', 'Core banking environments'],
    targets: ['Global', 'Bangladesh'],
    archived: true,
    archive_reason: 'RaaS brand collapsed in an exit scam in early 2024; affiliates migrated to other brands. Retained for the Bangladesh incident record.',
    description: 'Rust-based ransomware-as-a-service whose affiliates struck Bangladesh Krishi Bank in 2023, with reporting citing roughly 170GB of data compromised and a core banking system encrypted — BGD e-GOV CIRT attended on site to assess recoverability. The same period saw a US$5m extortion demand against Biman Bangladesh Airlines over 100GB of data, with the CERT having warned the airline of malware on an open back-door in its server two days before the attack. Both cases illustrate the structural problem the national CERT names publicly: advisories issued, advisories ignored. The brand itself exit-scammed in 2024 and is archived here; its affiliates did not retire, they rebranded.',
    ttps: [
      ['T1078', 'Valid Accounts', 'initial-access'],
      ['T1133', 'External Remote Services', 'initial-access'],
      ['T1486', 'Data Encrypted for Impact', 'impact'],
      ['T1490', 'Inhibit System Recovery', 'impact'],
      ['T1567.002', 'Exfiltration to Cloud Storage', 'exfiltration'],
      ['T1562.001', 'Disable or Modify Tools', 'defense-evasion'],
      ['T1021.001', 'Remote Desktop Protocol', 'lateral-movement']
    ],
    malware: [['ALPHV/BlackCat encryptor', 'Rust encryptor with Windows/Linux/ESXi builds'], ['ExMatter / Exbyte', 'Bespoke exfiltration tooling']],
    cves: ['CVE-2021-44228', 'CVE-2023-27350'],
    infra: ['Tor leak site with victim shaming', 'Affiliate-operated access brokers'],
    campaigns: [
      { name: 'Bangladesh Krishi Bank ransomware', date: '2023-07', summary: 'Core banking system encrypted; ~170GB reported compromised; CERT on-site damage assessment.', source: 'The Daily Star / press reporting' },
      { name: 'Biman Bangladesh extortion', date: '2023-03', summary: 'US$5m demand over 100GB of financial, HR, training and satellite-communications data.', source: 'The Daily Star' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'Shadow copy deletion (pre-encryption)', query: 'DeviceProcessEvents\n| where ProcessCommandLine has_any ("vssadmin delete shadows","wbadmin delete catalog","bcdedit /set {default} recoveryenabled no")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine' }
    ],
    sources: [
      { name: 'The Daily Star — Krishi Bank ransomware / Biman extortion', url: 'https://www.thedailystar.net/news/bangladesh/crime-justice/news/hackers-feast-government-sites-3364261' },
      { name: 'CISA — #StopRansomware: ALPHV Blackcat', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a' }
    ]
  },

  {
    id: 'gentlemen',
    name: 'The Gentlemen',
    apt: 'RaaS',
    aka: 'Gentlemen ransomware',
    country: 'Unknown',
    agency: 'Ransomware-as-a-Service',
    motivation: 'financial',
    confidence: 'moderate',
    active_since: 2025,
    last_seen: 2026,
    bd_relevance: 88,
    bd_status: 'confirmed',
    sectors: ['Manufacturing', 'Banking & Finance', 'Healthcare', 'Government', 'RMG & Textiles'],
    bd_targets: ['Bangladeshi enterprises flagged by the national CERT', 'Windows/ESXi estates', 'Active Directory environments'],
    targets: ['Bangladesh', 'Asia-Pacific', 'Global'],
    description: 'A rapidly scaling ransomware-as-a-service operation that BGD e-GOV CIRT called out by name on 9 August 2026 in an advisory titled "The Gentlemen Ransomware: A Rapidly Scaling RaaS Threat Targeting Bangladesh" — one of the few occasions the national CERT has named a criminal brand as targeting the country rather than merely being globally active. Treat it as the current top-of-list ransomware risk for Bangladeshi enterprises, particularly the RMG/manufacturing and financial sectors where downtime cost is highest and OT/ERP recovery is slowest.',
    ttps: [
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1078', 'Valid Accounts', 'initial-access'],
      ['T1486', 'Data Encrypted for Impact', 'impact'],
      ['T1490', 'Inhibit System Recovery', 'impact'],
      ['T1489', 'Service Stop', 'impact'],
      ['T1048', 'Exfiltration Over Alternative Protocol', 'exfiltration'],
      ['T1484.001', 'Group Policy Modification', 'defense-evasion']
    ],
    malware: [['Gentlemen encryptor', 'Windows and ESXi builds'], ['Commodity exfil tooling', 'Rclone/WinSCP-style staged exfiltration']],
    cves: [],
    infra: ['Affiliate-supplied initial access', 'GPO-based mass deployment'],
    campaigns: [
      { name: 'Gentlemen RaaS targeting Bangladesh', date: '2026-08-09', summary: 'National CERT advisory naming Bangladesh as a target geography for the RaaS operation.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'GPO-driven mass binary deployment', query: 'DeviceProcessEvents\n| where InitiatingProcessFileName =~ "gpscript.exe" or ProcessCommandLine has "\\\\SYSVOL\\\\"\n| summarize hosts=dcount(DeviceName), any(ProcessCommandLine) by bin(Timestamp, 1h)\n| where hosts > 5' }
    ],
    sources: [{ name: 'BGD e-GOV CIRT — The Gentlemen Ransomware advisory', url: 'https://www.cirt.gov.bd/advisories' }]
  },

  {
    id: 'incransom',
    name: 'INC Ransom',
    apt: 'RaaS',
    aka: 'INC Ransomware · Lynx (successor overlap)',
    country: 'Unknown',
    agency: 'Ransomware-as-a-Service',
    motivation: 'financial',
    confidence: 'high',
    active_since: 2023,
    last_seen: 2026,
    bd_relevance: 68,
    bd_status: 'assessed',
    sectors: ['Government', 'Healthcare', 'Manufacturing', 'Education', 'Virtualisation estates'],
    bd_targets: ['Enterprise server estates', 'VMware ESXi clusters', 'Active Directory domains', 'Legacy/mainframe-adjacent systems'],
    targets: ['Asia-Pacific', 'Europe', 'Global'],
    description: 'BGD e-GOV CIRT analysed INC Ransom in July 2026 after exposed affiliate infrastructure revealed payloads compiled for Windows, Linux, VMware ESXi, IBM Z (s390x), PowerPC, SPARC64 and RISC-V — an unusual push into enterprise and mainframe architectures. The exposed servers held Active Directory reconnaissance, GPO deployment scripts, Kerberos credential caches, DPAPI domain backup master keys, administrator NTLM hashes and OpenVPN persistence configs. No Bangladeshi victim was confirmed at publication, but the CERT advised organisations running virtualisation platforms, AD and legacy computing to review exposure — the profile matches Bangladesh\'s banking, telecom and government datacentre estate closely.',
    ttps: [
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1003.006', 'DCSync', 'credential-access'],
      ['T1555.004', 'Windows Credential Manager / DPAPI', 'credential-access'],
      ['T1550.003', 'Pass the Ticket', 'lateral-movement'],
      ['T1484.001', 'Group Policy Modification', 'defense-evasion'],
      ['T1486', 'Data Encrypted for Impact', 'impact'],
      ['T1133', 'External Remote Services (OpenVPN persistence)', 'persistence']
    ],
    malware: [['INC encryptor (multi-arch)', 'Curve25519 + Salsa20; Windows, Linux, ESXi, s390x, PowerPC, SPARC64, RISC-V builds'], ['Custom exfil tooling', 'HR database, ERP backup and executive desktop collection']],
    cves: ['CVE-2023-3519', 'CVE-2024-21412'],
    infra: ['Staging servers with GPO deployment scripts', 'OpenVPN-based long-term access', 'Exposed operational directories (~675MB tooling)'],
    campaigns: [
      { name: 'Cross-platform APAC campaign', date: '2026-07-05', summary: 'National CERT analysis of multi-architecture payloads and affiliate tooling; APAC-wide targeting.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'DPAPI domain backup key access', query: 'DeviceEvents\n| where ActionType == "LsassAccess" or AdditionalFields has "BackupKey"\n| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields' },
      { platform: 'SPL', title: 'ESXi — unexpected SSH enable + mass VM power-off', query: 'index=esxi ("SSH access enabled" OR "vim.VirtualMachine.powerOff")\n| stats count by host, user\n| where count > 10' }
    ],
    sources: [{ name: 'BGD e-GOV CIRT — INC Ransomware advisory (Jul 2026)', url: 'https://www.cirt.gov.bd/advisories/inc-ransomware-july-2026' }]
  },

  {
    id: 'goldfactory',
    name: 'GoldFactory',
    apt: 'GoldFactory',
    aka: 'GoldPickaxe / GoldDigger operators',
    country: 'Unknown',
    agency: 'Organised cybercrime (Chinese-speaking, assessed)',
    motivation: 'financial',
    confidence: 'high',
    active_since: 2023,
    last_seen: 2026,
    bd_relevance: 90,
    bd_status: 'confirmed',
    sectors: ['Banking & Finance', 'Mobile Financial Services', 'Digital Identity / e-KYC', 'Government services'],
    bd_targets: ['Mobile banking and MFS users', 'e-KYC and biometric onboarding flows', 'NID-linked digital identity services'],
    targets: ['Bangladesh', 'Thailand', 'Vietnam', 'Asia-Pacific'],
    description: 'BGD e-GOV CIRT issued a Bangladesh advisory on 21 July 2026 for GoldFactory\'s GoldPickaxe — a mobile banking trojan that steals facial biometric data, identity documents and SMS to defeat e-KYC and biometric authentication, with iOS and Android variants distributed through fake government-service and banking apps. This is the single most consequential criminal threat to Bangladesh\'s digital-finance stack: MFS penetration is extremely high, NID-linked e-KYC underpins account opening, and biometric liveness checks are increasingly the only control standing between a stolen identity and a funded account. Harvested faces are used to build deepfake-assisted verification bypasses, so the loss is permanent in a way password theft is not.',
    ttps: [
      ['T1660', 'Phishing (mobile)', 'initial-access'],
      ['T1444', 'Masquerade as Legitimate Application', 'defense-evasion'],
      ['T1636.004', 'Protected User Data: SMS Messages', 'collection'],
      ['T1512', 'Video Capture', 'collection'],
      ['T1533', 'Data from Local System (documents, images)', 'collection'],
      ['T1517', 'Access Notifications', 'collection'],
      ['T1437.001', 'Standard Application Layer Protocol', 'command-and-control']
    ],
    malware: [
      ['GoldPickaxe (iOS/Android)', 'Harvests facial biometrics, ID documents and SMS for e-KYC bypass'],
      ['GoldDigger / GoldDiggerPlus', 'Android banking trojan with accessibility-service abuse'],
      ['GoldKefu', 'Embedded trojan with fake bank support chat']
    ],
    cves: [],
    infra: ['TestFlight / MDM profile abuse for iOS distribution', 'Fake government-service and bank app stores', 'Smishing and LINE/WhatsApp lures'],
    campaigns: [
      { name: 'GoldPickaxe vs e-KYC and digital identity (BD advisory)', date: '2026-07-21', summary: 'National CERT advisory on biometric-stealing mobile banking trojan targeting e-KYC and digital identity systems.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'MDM profile install outside enrolment workflow (mobile MDM logs)', query: 'MobileDeviceEvents\n| where ActionType == "ProfileInstalled"\n| where InitiatingSource !in ("CorporateMDM")\n| project Timestamp, DeviceId, ProfileName, InitiatingSource' },
      { platform: 'SPL', title: 'e-KYC liveness pass from device with new IMEI + fresh account', query: 'index=ekyc action=liveness_pass\n| join type=inner account_id [search index=core_banking action=account_open earliest=-7d]\n| stats count by device_imei, account_id, src_ip\n| where count > 1' }
    ],
    sources: [
      { name: 'BGD e-GOV CIRT — GoldFactory / GoldPickaxe advisory', url: 'https://www.cirt.gov.bd/advisories' },
      { name: 'Group-IB — GoldFactory / GoldPickaxe research', url: 'https://www.group-ib.com/blog/goldfactory-ios-trojan/' }
    ]
  },

  {
    id: 'crimeware-bd',
    name: 'BD Commodity Crimeware Cluster',
    apt: 'Unattributed',
    aka: 'Nymaim/Avalanche · AsyncRAT · NodeStealer · Lumma · Mirai/MikroTik botnets',
    country: 'Unknown',
    agency: 'Financially motivated criminal ecosystem',
    motivation: 'financial',
    confidence: 'high',
    active_since: 2019,
    last_seen: 2026,
    bd_relevance: 86,
    bd_status: 'confirmed',
    sectors: ['All sectors', 'SMB & retail', 'Government', 'Education', 'Home/ISP subscribers'],
    bd_targets: ['Windows endpoints nationwide', 'Facebook business accounts', 'MikroTik and IoT routers', 'Gambling-lure victims'],
    targets: ['Bangladesh'],
    description: 'The background radiation of Bangladeshi cyberspace, and statistically the thing most likely to hit a given organisation. BGD e-GOV CIRT confirmed Nymaim / Avalanche-Nymaim loader activity inside Bangladesh (1 April 2026), an AsyncRAT campaign running off fraudulent gambling infrastructure aimed at Bangladeshi users (17 May 2026), Python NodeStealer evolving into full spyware harvesting browser credentials, clipboard, keystrokes and Facebook business account intelligence (6 September 2026), and a global "Error524" smishing campaign hitting multiple Bangladeshi sectors (13 April 2026). Its 2026 Eid alert enumerated the live clusters: Mirai and MikroTik botnets, Avalanche, Hajime, Emotet, Trickbot, Android BadBox/Void/Hummer, plus Cobalt Strike and ShadowPad. In May 2026 the CERT reported 55+ distinct malware strains in a single week and 160+ variants propagating nationally. Kaspersky telemetry has previously ranked Bangladesh worst in the world for Trojan encounter rate (3.69% of users).',
    ttps: [
      ['T1566.002', 'Spearphishing Link', 'initial-access'],
      ['T1660', 'Smishing', 'initial-access'],
      ['T1204.002', 'Malicious File', 'execution'],
      ['T1059.006', 'Python', 'execution'],
      ['T1555.003', 'Credentials from Web Browsers', 'credential-access'],
      ['T1115', 'Clipboard Data', 'collection'],
      ['T1056.001', 'Keylogging', 'collection'],
      ['T1583.005', 'Botnet', 'resource-development'],
      ['T1498', 'Network Denial of Service', 'impact'],
      ['T1608.001', 'Upload Malware', 'resource-development']
    ],
    malware: [
      ['Nymaim / Avalanche-Nymaim', 'Multi-stage loader historically fronting banking trojans and ransomware — confirmed active in BD'],
      ['AsyncRAT', 'Commodity RAT delivered via fraudulent gambling sites targeting Bangladeshi users'],
      ['Python NodeStealer', 'Browser, credential, clipboard and keylogging spyware; Facebook business account theft'],
      ['Lumma Stealer', 'Fake-CAPTCHA delivery chains flagged by the CERT'],
      ['Mirai / MikroTik botnets', 'IoT and router botnets used for DDoS against BD portals and banks'],
      ['Android BadBox / Void / Hummer', 'Pre-installed and dropped mobile malware']
    ],
    cves: ['CVE-2026-21858', 'CVE-2025-14847', 'CVE-2018-14847'],
    infra: ['Fraudulent gambling sites', 'PhaaS smishing kits ("Error524")', 'Compromised MikroTik routers as proxy/DDoS nodes', 'Fake CAPTCHA pages'],
    campaigns: [
      { name: 'Nymaim loader activity detected in Bangladesh', date: '2026-04-01', summary: 'National CERT confirms Nymaim/Avalanche loader activity on Bangladeshi networks.', source: 'BGD e-GOV CIRT' },
      { name: 'AsyncRAT via fraudulent gambling infrastructure', date: '2026-05-17', summary: 'Gambling-lure campaign delivering AsyncRAT to Bangladeshi victims.', source: 'BGD e-GOV CIRT' },
      { name: 'Python NodeStealer full spyware evolution', date: '2026-09-06', summary: 'Credential, clipboard, keylogging and Facebook business account theft.', source: 'BGD e-GOV CIRT' },
      { name: '"Error524" smishing across BD sectors', date: '2026-04-13', summary: 'PhaaS-driven SMS phishing redirecting victims to credential harvesting.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'KQL', title: 'Python interpreter writing to browser profile paths', query: 'DeviceFileEvents\n| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe")\n| where FolderPath has_any (@"\\User Data\\", @"\\Login Data", @"\\Cookies")\n| project Timestamp, DeviceName, FolderPath, InitiatingProcessCommandLine' },
      { platform: 'SPL', title: 'MikroTik router outbound scanning / DDoS participation', query: 'index=netflow src_ip IN (router_subnet)\n| stats dc(dest_ip) as targets, sum(bytes) as vol by src_ip, dest_port\n| where targets > 500' }
    ],
    sources: [
      { name: 'BGD e-GOV CIRT — advisories index', url: 'https://www.cirt.gov.bd/advisories' },
      { name: 'BGD e-GOV CIRT — Eid holiday alert (malware cluster list)', url: 'https://www.cirt.gov.bd/alerts/security-during-long-holiday-march-26' },
      { name: 'TBS News — Bangladesh highest risk of Trojan attacks (Kaspersky)', url: 'https://www.tbsnews.net/tech/bangladesh-highest-risk-ransomware-trojan-attacks-482062' }
    ]
  },

  /* --------------------------------------------------------- Exposure-led */
  {
    id: 'mass-exploitation',
    name: 'Opportunistic Mass Exploitation',
    apt: 'Multiple / scanners',
    aka: 'EOL IIS · MongoBleed · Ni8mare (n8n) · Magento · Axios npm',
    country: 'Unknown',
    agency: 'Mixed: criminal, state-adjacent, research scanners',
    motivation: 'mixed',
    confidence: 'high',
    active_since: 2020,
    last_seen: 2026,
    bd_relevance: 93,
    bd_status: 'confirmed',
    sectors: ['All sectors', 'Government', 'Education', 'Hosting & ISP', 'E-commerce'],
    bd_targets: ['452 BD IPs running end-of-life IIS', '80 exposed MongoDB instances', 'Self-hosted n8n instances', 'Magento storefronts', 'Node.js build pipelines'],
    targets: ['Bangladesh'],
    description: 'Not a group — the aggregate of internet-wide exploitation that lands on Bangladesh because of exposed, unpatched or end-of-life infrastructure. BGD e-GOV CIRT quantifies it repeatedly: 452 unique Bangladeshi IPs running end-of-life Microsoft IIS (March 2026, against 511,000 worldwide); 80 internet-exposed and misconfigured MongoDB instances vulnerable to "MongoBleed" (CVE-2025-14847); Bangladeshi hosts affected by "Ni8mare", an unauthenticated RCE in n8n (CVE-2026-21858); defacement artefacts on government infrastructure linked to global Magento exploitation (May 2026); and the compromised Axios npm package deploying a RAT into Node.js environments (April 2026). For most Bangladeshi organisations this is the realistic breach path — and the cheapest one to close.',
    ttps: [
      ['T1595.002', 'Vulnerability Scanning', 'reconnaissance'],
      ['T1190', 'Exploit Public-Facing Application', 'initial-access'],
      ['T1195.001', 'Compromise Software Dependencies', 'initial-access'],
      ['T1505.003', 'Web Shell', 'persistence'],
      ['T1078', 'Valid Accounts', 'persistence'],
      ['T1213', 'Data from Information Repositories', 'collection'],
      ['T1491.002', 'External Defacement', 'impact']
    ],
    malware: [['Commodity web shells', 'Dropped on exploited IIS/Magento hosts'], ['Axios npm RAT', 'Malicious package versions published from a hijacked maintainer account'], ['Cryptominers', 'Frequent post-exploitation payload on exposed hosts']],
    cves: ['CVE-2026-21858', 'CVE-2025-14847', 'CVE-2024-34102', 'CVE-2023-20198'],
    infra: ['Mass scanners (Shodan-visible surface)', 'Public exploit PoCs weaponised within hours', 'npm registry supply chain'],
    campaigns: [
      { name: 'EOL IIS exposure in Bangladesh', date: '2026-03-24', summary: '452 Bangladeshi IPs running unsupported IIS; CERT urges inventory, isolation and migration.', source: 'BGD e-GOV CIRT' },
      { name: 'MongoBleed exposure sweep', date: '2026', summary: '80 misconfigured internet-exposed MongoDB instances identified nationally (CVE-2025-14847).', source: 'BGD e-GOV CIRT' },
      { name: 'Ni8mare — n8n unauthenticated RCE', date: '2026', summary: 'Critical RCE (CVE-2026-21858) affecting self-hosted automation servers in Bangladesh.', source: 'BGD e-GOV CIRT' },
      { name: 'Axios npm package compromise', date: '2026-04-01', summary: 'Hijacked maintainer account published malicious Axios versions deploying a RAT.', source: 'BGD e-GOV CIRT' }
    ],
    iocs: [],
    hunt: [
      { platform: 'SPL', title: 'Inventory: internet-facing EOL IIS banners', query: 'index=web sourcetype=nginx:proxy OR sourcetype=iis\n| rex field=server_header "Microsoft-IIS/(?<iis_ver>\\d+\\.\\d+)"\n| where iis_ver < 10.0\n| stats count by host, iis_ver' },
      { platform: 'KQL', title: 'New npm dependency introducing outbound C2', query: 'DeviceNetworkEvents\n| where InitiatingProcessFileName =~ "node.exe"\n| where isnotempty(RemoteUrl) and RemoteUrl !has "registry.npmjs.org"\n| summarize count() by DeviceName, RemoteUrl, InitiatingProcessCommandLine' }
    ],
    sources: [
      { name: 'BGD e-GOV CIRT — EOL IIS servers in Bangladesh', url: 'https://www.cirt.gov.bd/advisories/end-of-life-microsoft-iis-servers-in-bangladesh' },
      { name: 'BGD e-GOV CIRT — advisories index (MongoBleed, Ni8mare, Axios)', url: 'https://www.cirt.gov.bd/advisories' }
    ]
  }
];

/* National incident record — the spine of the Threat Landscape timeline. */
export const INCIDENTS = [
  { date: '2013', title: 'Sonali Bank fraudulent SWIFT transfers', org: 'Sonali Bank', sector: 'Banking & Finance', severity: 'high', actor: 'Unattributed (re-examined post-2016)', summary: 'US$250,000 removed via fraudulent SWIFT transfers; treated as a cold case until the 2016 central bank heist prompted re-examination.', source: 'Bangladesh Police / press reporting', url: 'https://en.wikipedia.org/wiki/Bangladesh_Bank_robbery' },
  { date: '2016-02', title: 'Bangladesh Bank SWIFT heist — US$81m', org: 'Bangladesh Bank', sector: 'Central Bank / SWIFT', severity: 'critical', actor: 'Lazarus Group', summary: '35 fraudulent instructions against the New York Fed account; US$101m moved, US$81m lost to Manila. BGD e-GOV CIRT was established in the aftermath.', source: 'BAE Systems / Reuters / US DOJ', url: 'https://en.wikipedia.org/wiki/Bangladesh_Bank_robbery' },
  { date: '2021-08', title: 'Bitter begins targeting Bangladeshi government', org: 'Elite government entity / RAB', sector: 'Government', severity: 'high', actor: 'Bitter (APT-C-08)', summary: 'Spear-phishing of Rapid Action Battalion officers with Equation Editor exploits delivering the ZxxZ trojan; disclosed by Cisco Talos in May 2022.', source: 'Cisco Talos', url: 'https://blog.talosintelligence.com/bitter-apt-adds-bangladesh-to-their/' },
  { date: '2022-07', title: 'Sustained Bitter campaign vs military entities', org: 'Bangladesh military', sector: 'Military & Defence', severity: 'high', actor: 'Bitter (APT-C-08)', summary: 'Almond RAT added; ZxxZ C2 separator changed to evade signatures.', source: 'SECUINFRA', url: 'https://thehackernews.com/2022/07/bitter-apt-hackers-continue-to-target.html' },
  { date: '2023-03', title: 'Biman Bangladesh Airlines extortion', org: 'Biman Bangladesh Airlines', sector: 'Aviation', severity: 'critical', actor: 'Ransomware (unattributed)', summary: 'US$5m demanded over 100GB of financial, HR, training and satellite-communications data; CERT had warned of an open back door two days earlier.', source: 'The Daily Star', url: 'https://www.thedailystar.net/news/bangladesh/crime-justice/news/hackers-feast-government-sites-3364261' },
  { date: '2023-07', title: 'BDRIS citizen data exposure', org: 'Birth & Death Registration (BDRIS)', sector: 'Government', severity: 'critical', actor: 'Unattributed', summary: 'Birth dates and NID numbers exposed via government systems — enough to pivot into names, addresses and further personal data through public tools.', source: 'The Daily Star / BGD e-GOV CIRT', url: 'https://www.thedailystar.net/news/bangladesh/crime-justice/news/hackers-feast-government-sites-3364261' },
  { date: '2023-07', title: 'Bangladesh Krishi Bank ransomware', org: 'Bangladesh Krishi Bank', sector: 'Banking & Finance', severity: 'critical', actor: 'ALPHV / BlackCat', summary: 'Core banking system encrypted; ~170GB reported compromised; national CERT conducted on-site damage assessment.', source: 'The Daily Star / press', url: 'https://www.thedailystar.net/news/bangladesh/crime-justice/news/hackers-feast-government-sites-3364261' },
  { date: '2023-08', title: '15 August targeting wave', org: 'CII, banks, healthcare, government', sector: 'Multi-sector', severity: 'high', actor: 'Regional hacktivist cluster', summary: 'CERT pre-warned of coordinated attacks on critical information infrastructure; defacements and data-leak claims followed.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories' },
  { date: '2025-07-25', title: 'National situational alert — CII, energy, banks', org: 'National', sector: 'Multi-sector', severity: 'high', actor: 'Multiple', summary: 'CERT warns of potential large-scale attacks on Bangladesh ICT infrastructure: web application exploitation, defacement, credential compromise and DDoS.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/alerts/cii-energy-banks-2025-07' },
  { date: '2025-08 → 2025-10', title: 'SideWinder credential harvesting vs defence portals', org: 'DGDP · BAF · DGFI · National Webmail', sector: 'Military & Defence', severity: 'critical', actor: 'SideWinder', summary: '14+ phishing pages spoofing Bangladeshi defence and government portals on Netlify/pages.dev, funnelling credentials to centralised collectors.', source: 'Hunt.io', url: 'https://hunt.io/blog/operation-southnet-sidewinder-south-asia-maritime-phishing' },
  { date: '2026-03-24', title: '452 Bangladeshi IPs running end-of-life IIS', org: 'National exposure', sector: 'Multi-sector', severity: 'high', actor: 'Opportunistic mass exploitation', summary: 'National scan finds 452 unique BD IPs on unsupported Microsoft IIS; CERT urges immediate inventory, isolation and migration.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories/end-of-life-microsoft-iis-servers-in-bangladesh' },
  { date: '2026-04-01', title: 'Nymaim loader activity detected in Bangladesh', org: 'National', sector: 'Multi-sector', severity: 'medium', actor: 'BD commodity crimeware', summary: 'Avalanche-Nymaim multi-stage loader activity confirmed on Bangladeshi networks.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories' },
  { date: '2026-05-03', title: 'Government web defacement linked to Magento exploitation', org: 'Government web estate', sector: 'Government', severity: 'medium', actor: 'Regional hacktivist cluster', summary: 'Defacement artefacts on Bangladeshi government infrastructure tied to a global Magento exploitation campaign.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories' },
  { date: '2026-07-21', title: 'GoldPickaxe biometric trojan advisory', org: 'Banking / e-KYC ecosystem', sector: 'Banking & Finance', severity: 'critical', actor: 'GoldFactory', summary: 'Mobile banking trojan stealing facial biometrics and identity documents to defeat e-KYC and digital identity verification.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories' },
  { date: '2026-07-30', title: 'SideWinder dual-format weaponised documents vs BD', org: 'Government & defence', sector: 'Military & Defence', severity: 'high', actor: 'SideWinder', summary: 'CERT advisory on spear-phishing using dual-format weaponised documents against Bangladeshi entities.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories' },
  { date: '2026-08-09', title: 'The Gentlemen RaaS named as targeting Bangladesh', org: 'Bangladeshi enterprises', sector: 'Multi-sector', severity: 'critical', actor: 'The Gentlemen', summary: 'National CERT names a rapidly scaling ransomware-as-a-service operation as actively targeting Bangladesh.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories' },
  { date: '2026-08-17', title: 'DoNot (APT-C-35) espionage vs BD military & defence', org: 'Bangladesh Air Force / defence establishment', sector: 'Military & Defence', severity: 'critical', actor: 'DoNot Team', summary: 'Geofenced RTF lure built on a BAF officer biography; AES-encrypted DLL implant with OneDrive-themed scheduled-task persistence.', source: 'BGD e-GOV CIRT / Cyderes', url: 'https://www.cirt.gov.bd/advisories/donot-apt-c-35' },
  { date: '2026-09-17', title: 'SideWinder toolkit vs government & financial infrastructure', org: 'Government & financial sector', sector: 'Multi-sector', severity: 'high', actor: 'SideWinder', summary: 'Recovered toolkit with GeoServer/GeoTools, Laravel Ignition, Tomcat Manager and Redis exploitation plus weak-credential attacks.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories/sidewinder-associated-campaign' },
  { date: '2026-09-23', title: 'SideCopy MSHTA / LNK fileless RAT campaign', org: 'Government targets', sector: 'Government', severity: 'high', actor: 'SideCopy', summary: 'Spear-phishing with weaponised .LNK files, mshta.exe execution and multi-stage fileless RAT deployment.', source: 'BGD e-GOV CIRT', url: 'https://www.cirt.gov.bd/advisories/sidecopy-campaign-sep-26' }
];

/* Sector exposure model for Bangladesh (analyst-assigned, 0-100). */
export const SECTORS = [
  { name: 'Banking & Finance',            exposure: 96, note: 'Central bank heist precedent, RaaS pressure, e-KYC biometric theft, MFS scale' },
  { name: 'Military & Defence',           exposure: 94, note: 'Three separate India-nexus actors running live credential and implant campaigns' },
  { name: 'Government & Public Admin',    exposure: 91, note: 'Webmail credential harvesting, defacement waves, citizen-data exposure history' },
  { name: 'Telecom & ISP',                exposure: 82, note: 'Backbone/edge router exposure; PRC telecom-espionage pattern; DDoS transit' },
  { name: 'Energy & Power (OT/ICS)',      exposure: 78, note: 'Eastern Refinery and Moheshkhali LNG automation flagged as under-protected' },
  { name: 'Healthcare',                   exposure: 71, note: 'Ransomware and defacement targets with weak patching and legacy IIS' },
  { name: 'RMG & Manufacturing',          exposure: 69, note: 'Export-critical downtime cost; ERP/ESXi estates; low security maturity' },
  { name: 'Aviation & Transport',         exposure: 66, note: 'Biman extortion precedent; airport and logistics IT' },
  { name: 'Education & Research',         exposure: 58, note: 'Exposed portals and databases; frequent defacement victims' },
  { name: 'Media & Civil Society',        exposure: 54, note: 'Surveillance-ware and account-takeover risk for journalists and NGOs' }
];
