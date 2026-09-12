#!/usr/bin/env python
"""Build the SOC knowledge base that grounds every AI verdict.

Produces data/kb/corpus.json — the only facts the model is permitted to cite —
and optionally data/kb/embeddings.npy for dense retrieval.

Sources:
  1. MITRE ATT&CK Enterprise (STIX)  — techniques, tactics, detection, mitigations
  2. Windows / Sysmon event reference — curated, covering this corpus's event IDs
  3. LOLBAS binary abuse notes        — curated
  4. The platform's own detection rules
  5. Response playbooks               — curated, feeds the Playbooks tab

Replaces soc-sentinel/src/utils/mitreMapper.js, which covered 11 techniques by
keyword and defaulted everything else to T1190.

Usage:
    python scripts/build_kb.py [--no-embeddings]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
KB_DIR = BASE_DIR / "data" / "kb"
STIX_PATH = KB_DIR / "enterprise-attack.json"
CORPUS_PATH = KB_DIR / "corpus.json"
EMBED_PATH = KB_DIR / "embeddings.npy"
RULES_PATH = BASE_DIR / "rules" / "detection_rules.yml"

EMBED_MODEL = "BAAI/bge-small-en-v1.5"


# --------------------------------------------------------------------------
# 1. MITRE ATT&CK
# --------------------------------------------------------------------------

def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_attack_chunks(stix_path: Path) -> list[dict]:
    """One chunk per live technique, joined with its detection and mitigations.

    In the current ATT&CK spec x_mitre_detection is gone; detection guidance
    lives in x-mitre-detection-strategy objects linked by a 'detects'
    relationship, each pointing at x-mitre-analytic objects that carry the
    actual log-source guidance. Mitigations arrive via 'mitigates'.
    """
    data = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = data["objects"]
    by_id = {o["id"]: o for o in objects}

    techniques = [
        o
        for o in objects
        if o["type"] == "attack-pattern"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    ]

    # technique stix id -> [detection strategy objects]
    detections: dict[str, list[dict]] = {}
    mitigations: dict[str, list[dict]] = {}
    parents: dict[str, str] = {}

    for rel in objects:
        if rel["type"] != "relationship":
            continue
        rtype = rel["relationship_type"]
        src, tgt = rel.get("source_ref", ""), rel.get("target_ref", "")
        if rtype == "detects" and tgt.startswith("attack-pattern--"):
            strategy = by_id.get(src)
            if strategy:
                detections.setdefault(tgt, []).append(strategy)
        elif rtype == "mitigates" and tgt.startswith("attack-pattern--"):
            coa = by_id.get(src)
            if coa:
                mitigations.setdefault(tgt, []).append(coa)
        elif rtype == "subtechnique-of":
            parents[src] = tgt

    chunks: list[dict] = []
    for tech in techniques:
        tid = _attack_id(tech)
        if not tid:
            continue

        tactics = [
            p["phase_name"].replace("-", " ")
            for p in tech.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        platforms = tech.get("x_mitre_platforms", [])

        parts = [f"{tid} — {tech['name']}"]
        if tactics:
            parts.append(f"Tactic: {', '.join(tactics)}.")
        if platforms:
            parts.append(f"Platforms: {', '.join(platforms)}.")

        parent_ref = parents.get(tech["id"])
        if parent_ref and (parent := by_id.get(parent_ref)):
            parts.append(f"Sub-technique of {_attack_id(parent)} — {parent['name']}.")

        parts.append(tech.get("description", "").strip())

        # Detection guidance, flattened from strategies -> analytics.
        detection_texts: list[str] = []
        log_sources: set[str] = set()
        for strategy in detections.get(tech["id"], []):
            detection_texts.append(strategy.get("name", ""))
            for aref in strategy.get("x_mitre_analytic_refs", []):
                analytic = by_id.get(aref)
                if not analytic:
                    continue
                if desc := analytic.get("description", "").strip():
                    detection_texts.append(desc)
                for ls in analytic.get("x_mitre_log_source_references", []):
                    if name := ls.get("name"):
                        channel = ls.get("channel", "")
                        log_sources.add(f"{name} {channel}".strip())
        if detection_texts:
            parts.append("DETECTION: " + " ".join(detection_texts))
        if log_sources:
            parts.append("LOG SOURCES: " + "; ".join(sorted(log_sources)))

        if mits := mitigations.get(tech["id"], []):
            names = sorted({m.get("name", "") for m in mits if m.get("name")})
            parts.append("MITIGATIONS: " + "; ".join(names))

        chunks.append(
            {
                "id": f"attack:{tid}",
                "kind": "attack_technique",
                "title": f"{tid} — {tech['name']}",
                "technique_id": tid,
                "tactics": tactics,
                "platforms": platforms,
                "text": "\n".join(p for p in parts if p),
            }
        )

    return chunks


# --------------------------------------------------------------------------
# 2. Windows / Sysmon event reference
# --------------------------------------------------------------------------
# Curated to cover the event IDs that actually dominate this dataset
# (5145, Sysmon 1/7/11/13/3, 4624, 4625) plus the common escalation and
# persistence events. The benign baseline matters as much as the suspicious
# reading: without it the model escalates ordinary administration.

WINDOWS_EVENTS = [
    ("4624", "Successful account logon",
     "An account successfully logged on. Key fields: TargetUserName, LogonType, "
     "IpAddress, WorkstationName, LogonProcessName. LogonType 2 is interactive, "
     "3 network, 4 batch, 5 service, 7 unlock, 8 network cleartext, 9 new "
     "credentials (runas /netonly, often seen with pass-the-hash), 10 RemoteInteractive "
     "(RDP), 11 cached interactive. BENIGN BASELINE: type 3 and 5 logons occur "
     "constantly from service accounts and machine accounts ending in $. "
     "SUSPICIOUS: type 10 from an unexpected source, type 9 paired with credential "
     "tooling, or a burst of type 3 across many hosts from one account."),
    ("4625", "Failed account logon",
     "An account failed to log on. Key fields: TargetUserName, IpAddress, "
     "LogonType, Status/SubStatus. SubStatus 0xC0000064 means the user does not "
     "exist, 0xC000006A means bad password, 0xC0000234 account locked out. "
     "BENIGN BASELINE: isolated failures are routine after password changes. "
     "SUSPICIOUS: many failures from one source in a short window (password "
     "guessing), or one password tried against many usernames (password spraying)."),
    ("4672", "Special privileges assigned to new logon",
     "Administrator-equivalent privileges were assigned at logon, such as "
     "SeDebugPrivilege or SeTakeOwnershipPrivilege. BENIGN BASELINE: normal for "
     "admin accounts and SYSTEM. SUSPICIOUS: paired with an unexpected account or "
     "immediately preceding credential access activity."),
    ("4688", "Process creation (Security log)",
     "A new process was created. Key fields: NewProcessName, CommandLine (only if "
     "command-line auditing is enabled), ParentProcessName, SubjectUserName. "
     "SUSPICIOUS: office applications or browsers spawning script interpreters, "
     "unusual parent-child chains, encoded command lines, or execution from "
     "user-writable paths such as AppData or Temp."),
    ("4720", "User account created",
     "A user account was created. BENIGN BASELINE: expected from IT provisioning "
     "during business hours. SUSPICIOUS: creation outside business hours, or "
     "followed shortly by 4732 (added to a privileged local group), which is a "
     "classic persistence pattern."),
    ("4732", "Member added to a security-enabled local group",
     "An account was added to a local group. SUSPICIOUS when the group is "
     "Administrators and the addition follows a recent 4720."),
    ("4698", "Scheduled task created",
     "A scheduled task was registered. Key fields: TaskName, TaskContent. "
     "BENIGN BASELINE: software updaters create tasks routinely. SUSPICIOUS: tasks "
     "invoking script interpreters, encoded commands, or binaries in Temp, and "
     "tasks created outside business hours."),
    ("4769", "Kerberos service ticket requested",
     "A Kerberos TGS ticket was requested. SUSPICIOUS: a burst of requests for many "
     "service accounts with RC4 encryption (ticket option 0x40810000, encryption "
     "type 0x17) indicates Kerberoasting."),
    ("4776", "Domain controller attempted credential validation",
     "NTLM credential validation. SUSPICIOUS: repeated failures across accounts, "
     "indicating spraying against the domain."),
    ("1102", "Audit log cleared",
     "The security audit log was cleared. Almost never legitimate on a server "
     "outside a documented maintenance action; a strong defense-evasion signal."),
    ("5145", "Network share object access checked",
     "Detailed file share access. Key fields: ShareName, RelativeTargetName, "
     "IpAddress, SubjectUserName. BENIGN BASELINE: extremely high volume in normal "
     "domain environments; this event alone is weak evidence. SUSPICIOUS: access to "
     "ADMIN$, C$ or IPC$ from a workstation, especially paired with service creation "
     "— the signature of remote execution tools such as PsExec."),
    ("7045", "Service installed",
     "A new service was installed. Key fields: ServiceName, ImagePath. SUSPICIOUS: "
     "random-looking service names, ImagePath pointing at Temp or a share, or "
     "command interpreters used as the service binary — the PsExec and Cobalt Strike "
     "lateral movement pattern."),
]

SYSMON_EVENTS = [
    ("1", "Sysmon process creation",
     "Full process creation with CommandLine, ParentImage, ParentCommandLine, Hashes, "
     "User and IntegrityLevel. The single most useful endpoint event. SUSPICIOUS: "
     "LOLBIN execution, encoded PowerShell, unusual parent-child lineage such as "
     "winword.exe spawning cmd.exe, or high integrity level from a normal user."),
    ("3", "Sysmon network connection",
     "A process initiated a network connection. Key fields: Image, DestinationIp, "
     "DestinationPort, DestinationHostname. SUSPICIOUS: connections from script "
     "interpreters or office applications, beaconing to one destination at regular "
     "intervals, or connections to raw IP addresses on uncommon ports."),
    ("7", "Sysmon image loaded",
     "A module was loaded into a process. High volume, so weak on its own. "
     "SUSPICIOUS: unsigned DLLs loaded from user-writable paths, or security-relevant "
     "DLLs loaded by an unexpected process — a signature of DLL side-loading."),
    ("8", "Sysmon CreateRemoteThread",
     "A process created a thread in another process. SUSPICIOUS: strongly associated "
     "with process injection, especially when the target is lsass.exe or explorer.exe."),
    ("10", "Sysmon process access",
     "A process opened a handle to another process. SUSPICIOUS: access to lsass.exe "
     "with GrantedAccess 0x1010 or 0x1410 is the classic credential-dumping signature."),
    ("11", "Sysmon file created",
     "A file was created. SUSPICIOUS: executables or scripts written to Temp, AppData "
     "or Startup folders, and files with double extensions."),
    ("12", "Sysmon registry key create/delete",
     "Registry key created or deleted. SUSPICIOUS when touching Run keys or service "
     "configuration."),
    ("13", "Sysmon registry value set",
     "A registry value was set. SUSPICIOUS: writes to "
     "HKLM or HKCU Software Microsoft Windows CurrentVersion Run, Winlogon Shell or "
     "Userinit, or image file execution options — all persistence mechanisms."),
    ("22", "Sysmon DNS query",
     "A process performed a DNS lookup. SUSPICIOUS: long high-entropy domain names "
     "suggesting DGA or DNS tunnelling, or lookups from non-browser processes."),
]


def build_event_chunks() -> list[dict]:
    chunks = []
    for eid, title, text in WINDOWS_EVENTS:
        chunks.append({
            "id": f"winevent:{eid}",
            "kind": "windows_event",
            "title": f"Windows Event ID {eid} — {title}",
            "event_id": eid,
            "text": f"Windows Security Event ID {eid}: {title}. {text}",
        })
    for eid, title, text in SYSMON_EVENTS:
        chunks.append({
            "id": f"sysmon:{eid}",
            "kind": "sysmon_event",
            "title": f"Sysmon Event ID {eid} — {title}",
            "event_id": eid,
            "text": f"Sysmon Event ID {eid}: {title}. {text}",
        })
    return chunks


# --------------------------------------------------------------------------
# 3. LOLBAS
# --------------------------------------------------------------------------

LOLBAS = [
    ("rundll32.exe", "Executes exported DLL functions. Abused to run arbitrary code "
     "while appearing to be a signed Microsoft binary. SUSPICIOUS: javascript: URLs, "
     "advpack.dll RegisterOCX, shell32.dll ShellExec_RunDLL, or a DLL path in Temp."),
    ("regsvr32.exe", "Registers DLLs. The 'Squiblydoo' technique uses /i: with a "
     "scrobj.dll scriptlet fetched over HTTP to execute code and bypass application "
     "allowlisting."),
    ("mshta.exe", "Executes HTML applications. Abused to run inline VBScript or "
     "JScript, often with a remote .hta URL."),
    ("certutil.exe", "Certificate utility. Abused with -urlcache -f to download files "
     "and with -decode to deobfuscate base64 payloads."),
    ("wmic.exe", "WMI command line. Abused for remote process creation "
     "(process call create) and for local discovery."),
    ("pcalua.exe", "Program Compatibility Assistant launcher. Abused purely as a "
     "proxy to launch another executable and break parent-child lineage."),
    ("msiexec.exe", "Installer. Abused to install a remote MSI package over HTTP."),
    ("cscript.exe / wscript.exe", "Windows Script Host. Executes VBScript and JScript, "
     "a common first-stage payload delivered by email."),
    ("powershell.exe", "SUSPICIOUS switches: -EncodedCommand or -enc (base64 payload), "
     "-ExecutionPolicy Bypass, -WindowStyle Hidden, -NoProfile, and in-memory download "
     "cradles using DownloadString, DownloadFile, IEX or Invoke-Expression."),
    ("schtasks.exe", "Creates scheduled tasks. Abused for persistence and for remote "
     "execution with the /S switch."),
    ("net.exe / net1.exe", "Abused for discovery (net user, net group, net view) and "
     "for lateral movement (net use against ADMIN$ or C$)."),
    ("psexec.exe", "Sysinternals remote execution. Creates a service on the target and "
     "copies a binary to ADMIN$. Produces 5145 on the share plus 7045 service install."),
]


def build_lolbas_chunks() -> list[dict]:
    return [
        {
            "id": f"lolbas:{name.split()[0].replace('.exe','')}",
            "kind": "lolbas",
            "title": f"LOLBAS — {name}",
            "text": f"{name}: {text}",
        }
        for name, text in LOLBAS
    ]


# --------------------------------------------------------------------------
# 4. The platform's own detection rules
# --------------------------------------------------------------------------

def build_rule_chunks(rules_path: Path) -> list[dict]:
    if not rules_path.exists():
        return []
    rules = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or []
    chunks = []
    for rule in rules:
        conditions = "; ".join(
            f"{c.get('field')} {c.get('operator')} {c.get('value')}"
            for c in rule.get("conditions", [])
        )
        chunks.append({
            "id": f"rule:{rule.get('id')}",
            "kind": "detection_rule",
            "title": f"{rule.get('id')} — {rule.get('name')}",
            "text": (
                f"Platform detection rule {rule.get('id')} '{rule.get('name')}' "
                f"(severity {rule.get('severity')}, type {rule.get('type')}). "
                f"{rule.get('description', '')} "
                f"Maps to {rule.get('mitre_technique', 'unknown')}. "
                f"Conditions: {conditions}."
            ),
        })
    return chunks


# --------------------------------------------------------------------------
# 5. Response playbooks
# --------------------------------------------------------------------------

PLAYBOOKS = [
    ("credential-access", "Credential Access / Credential Dumping",
     "CONTAIN: isolate the host from the network; force-reset every account that "
     "authenticated to it, starting with privileged accounts; invalidate Kerberos "
     "tickets by resetting krbtgt twice if a domain controller is implicated. "
     "ERADICATE: identify and remove the dumping tool; review persistence "
     "mechanisms on the host; audit group memberships for accounts added recently. "
     "RECOVER: rebuild the host from a known-good image rather than cleaning it; "
     "restore accounts once passwords are rotated. ESCALATE TO: IR lead and "
     "identity team immediately — credential theft spreads."),
    ("lateral-movement", "Lateral Movement",
     "CONTAIN: block the source host at the network layer; disable the account used "
     "for the movement; audit administrative share access across the estate. "
     "ERADICATE: remove services or scheduled tasks created on the destination hosts; "
     "hunt for the same tooling on every host the account touched. RECOVER: restore "
     "affected hosts and re-enable the account only after password rotation. "
     "ESCALATE TO: IR lead and the owners of every destination system."),
    ("persistence", "Persistence",
     "CONTAIN: snapshot the host before changing anything, so the mechanism is "
     "preserved for analysis. ERADICATE: remove the registry Run key, scheduled task, "
     "service or WMI subscription; hunt the same mechanism across the estate, since "
     "attackers reuse it. RECOVER: confirm the mechanism does not return on reboot. "
     "ESCALATE TO: IR lead and the asset owner."),
    ("privilege-escalation", "Privilege Escalation",
     "CONTAIN: disable the elevated account; revoke sessions and tokens. ERADICATE: "
     "patch the exploited vulnerability or correct the misconfiguration; review what "
     "the elevated context accessed. RECOVER: restore correct group memberships and "
     "verify with an access review. ESCALATE TO: IR lead, identity team and the "
     "vulnerability management owner."),
    ("defense-evasion", "Defense Evasion",
     "CONTAIN: preserve remaining logs immediately and forward them off-host; if "
     "audit logs were cleared, treat the host as compromised. ERADICATE: restore "
     "tampered security tooling and re-enable disabled protections. RECOVER: rebuild "
     "if logging integrity cannot be established. ESCALATE TO: IR lead — log "
     "destruction implies a deliberate operator."),
    ("command-and-control", "Command and Control",
     "CONTAIN: block the destination at the perimeter and sinkhole the domain; "
     "isolate the beaconing host. ERADICATE: identify and remove the implant; hunt "
     "for the same indicator across all egress logs. RECOVER: rebuild the host; "
     "monitor for re-establishment. ESCALATE TO: IR lead and network team."),
    ("execution", "Suspicious Execution",
     "CONTAIN: kill the process tree and isolate the host if the payload is unknown. "
     "ERADICATE: remove dropped files; determine the delivery vector, checking email "
     "and browser history. RECOVER: restore from backup if files were modified. "
     "ESCALATE TO: IR lead; notify the user's manager if delivery was via email."),
    ("discovery", "Discovery / Reconnaissance",
     "CONTAIN: usually no isolation needed alone, but raise monitoring on the account "
     "and host. ERADICATE: confirm whether discovery preceded other activity — it is "
     "rarely the whole story. RECOVER: no restoration typically required. "
     "ESCALATE TO: the hunt team, to look for what followed."),
    ("phishing", "Phishing / Initial Access",
     "CONTAIN: pull the message from all mailboxes; block the sender and any URLs; "
     "identify every recipient who clicked. ERADICATE: reset credentials for anyone "
     "who submitted them; scan clicked hosts for payloads. RECOVER: restore mailbox "
     "access and brief affected users. ESCALATE TO: IR lead and the email security "
     "team; legal if data was submitted."),
]


def build_playbook_chunks() -> list[dict]:
    return [
        {
            "id": f"playbook:{slug}",
            "kind": "playbook",
            "title": f"Response Playbook — {title}",
            "text": f"Incident response playbook for {title}. {text}",
        }
        for slug, title, text in PLAYBOOKS
    ]


# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-embeddings", action="store_true",
                        help="skip dense embeddings; BM25 retrieval still works")
    args = parser.parse_args()

    KB_DIR.mkdir(parents=True, exist_ok=True)

    if not STIX_PATH.exists():
        print(f"[!] Missing {STIX_PATH}", file=sys.stderr)
        print("    curl -sL -o data/kb/enterprise-attack.json \\", file=sys.stderr)
        print("      https://raw.githubusercontent.com/mitre/cti/master/"
              "enterprise-attack/enterprise-attack.json", file=sys.stderr)
        return 1

    corpus: list[dict] = []
    for label, chunks in [
        ("ATT&CK techniques", build_attack_chunks(STIX_PATH)),
        ("Windows/Sysmon events", build_event_chunks()),
        ("LOLBAS binaries", build_lolbas_chunks()),
        ("Detection rules", build_rule_chunks(RULES_PATH)),
        ("Response playbooks", build_playbook_chunks()),
    ]:
        print(f"[+] {label}: {len(chunks)}")
        corpus.extend(chunks)

    CORPUS_PATH.write_text(json.dumps(corpus, indent=1), encoding="utf-8")
    print(f"[+] Wrote {len(corpus)} chunks -> {CORPUS_PATH}")

    if args.no_embeddings:
        print("[i] Skipping embeddings (BM25 retrieval only).")
        return 0

    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("[i] sentence-transformers unavailable; BM25 retrieval only.")
        return 0

    print(f"[+] Encoding {len(corpus)} chunks with {EMBED_MODEL}...")
    model = SentenceTransformer(EMBED_MODEL)
    texts = [f"{c['title']}\n{c['text']}" for c in corpus]
    vectors = model.encode(
        texts, batch_size=64, normalize_embeddings=True, show_progress_bar=True
    )
    np.save(EMBED_PATH, vectors.astype("float32"))
    print(f"[+] Wrote embeddings {vectors.shape} -> {EMBED_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
