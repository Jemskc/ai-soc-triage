const RULES = [
  { patterns: ['brute force', 'brute-force', 'login fail', 'failed login', 'authentication fail', 'invalid login'], technique: 'T1110.001', name: 'Brute Force: Password Guessing' },
  { patterns: ['powershell', 'ps1', 'encoded command', '-enc', 'invoke-expression', 'iex('], technique: 'T1059.001', name: 'Command Scripting: PowerShell' },
  { patterns: ['rdp', 'remote desktop', 'lateral', 'pass-the-hash', 'wmi', 'psexec'], technique: 'T1021', name: 'Remote Services' },
  { patterns: ['privilege', 'escalat', 'uac bypass', 'token imperson', 'runas'], technique: 'T1078', name: 'Valid Accounts / Privilege Escalation' },
  { patterns: ['phishing', 'spearphish', 'malicious attachment', 'macro'], technique: 'T1566', name: 'Phishing' },
  { patterns: ['ransomware', 'encrypt', 'cryptolock'], technique: 'T1486', name: 'Data Encrypted for Impact' },
  { patterns: ['exfil', 'data transfer', 'large upload', 'dns tunnel'], technique: 'T1041', name: 'Exfiltration Over C2 Channel' },
  { patterns: ['persistence', 'registry run', 'scheduled task', 'autostart', 'startup'], technique: 'T1547', name: 'Boot or Logon Autostart Execution' },
  { patterns: ['defacement', 'web shell', 'sql inject', 'xss', 'rce', 'exploit'], technique: 'T1190', name: 'Exploit Public-Facing Application' },
  { patterns: ['port scan', 'nmap', 'recon', 'discovery', 'enumerat'], technique: 'T1046', name: 'Network Service Discovery' },
  { patterns: ['malware', 'virus', 'trojan', 'backdoor', 'rat'], technique: 'T1204', name: 'User Execution: Malicious File' },
];

export function getMitreTechnique(rule = '', message = '') {
  const text = `${rule} ${message}`.toLowerCase();
  for (const r of RULES) {
    if (r.patterns.some(p => text.includes(p))) {
      return { technique: r.technique, name: r.name };
    }
  }
  return { technique: 'T1190', name: 'Exploit Public-Facing Application' };
}
