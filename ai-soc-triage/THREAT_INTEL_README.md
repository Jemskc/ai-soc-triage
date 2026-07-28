# Automated Threat Intelligence for Phishing Analysis

## Overview

The SOC Sentinel platform now includes **automated threat intelligence enrichment** for phishing email analysis. When you receive a phishing alert, the system automatically checks all IOCs (Indicators of Compromise) against multiple threat intelligence sources **without requiring manual lookup on external websites**.

## What It Does

When an email is analyzed in the Phishing Tab, the system automatically:

1. **Extracts IOCs** from the email:
   - Origin IP addresses
   - Sender/Reply-To domains
   - URLs in the email body
   - File hashes from attachments

2. **Enriches each IOC** by querying:
   - **VirusTotal** - Domain/IP/URL/hash reputation from 70+ security vendors
   - **Whois Lookup** - Domain registration info, age, registrar
   - **AbuseIPDB** - IP abuse confidence score and reports
   - **Shodan** - Open ports, vulnerabilities, services on IPs

3. **Calculates risk scores** for each IOC based on:
   - VirusTotal detection ratio
   - Domain age (new domains < 30 days are suspicious)
   - IP abuse confidence score
   - Known vulnerabilities
   - Suspicious URL patterns

4. **Provides actionable recommendations**:
   - "Block IP X.X.X.X at firewall - flagged malicious by VT"
   - "Newly registered domain (3 days old) - common in phishing"
   - "High abuse score (87%) - consider blocking"

## Configuration

### Step 1: Get Free API Keys

| Service | Free Tier | Sign Up Link |
|---------|-----------|--------------|
| **VirusTotal** | 4 requests/min, 500/day | https://www.virustotal.com/gui/my-apikey |
| **AbuseIPDB** | 1,000 requests/day | https://www.abuseipdb.com/api |
| **Shodan** | 100 queries/month | https://account.shodan.io/ |
| **WhoisXML API** | 500 lookups/month | https://whoisxmlapi.com/ |

### Step 2: Add API Keys to `.env`

Copy `.env.example` to `.env` and add your keys:

```bash
cd /workspace/ai-soc-triage
cp .env.example .env
nano .env  # or use your preferred editor
```

Add your API keys:

```env
# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
WHOISXML_API_KEY=your_whoisxml_api_key_here
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

The `requests` library is required for API calls.

### Step 4: Restart the Backend

```bash
python src/api_server.py
```

## How It Works

### Without API Keys
If no API keys are configured, the system still works using:
- Local AI analysis (Qwen2.5-14B)
- SPF/DKIM/DMARC validation
- Pattern-based URL detection
- Attachment risk assessment

The AI will note: *"No external threat intel data available (API keys not configured)"*

### With API Keys
When API keys are configured:

1. **Automatic IOC Extraction** - Parses email for IPs, domains, URLs, hashes
2. **Parallel API Queries** - Checks each IOC against configured threat intel sources
3. **Intelligent Caching** - Results cached for 1 hour to avoid redundant API calls
4. **Risk Scoring** - Combines multiple signals into 0-100 risk score
5. **AI-Enhanced Analysis** - Threat intel findings fed to local LLM for final verdict

## Example Output

### API Response Structure

```json
{
  "analysis": "Verdict: MALICIOUS (95% confidence)\n\nAttack Technique: Credential Phishing...\n",
  "threat_intelligence": {
    "summary": {
      "overall_risk": "critical",
      "critical_iocs": 2,
      "high_risk_iocs": 1,
      "total_iocs_enriched": 5,
      "recommendations": [
        "Block domain microsft-login.com - flagged malicious by VT (45/72 engines)",
        "IP 185.220.101.1: AbuseIPDB score=98%",
        "Newly registered domain (2 days old) - common in phishing"
      ]
    },
    "iocs": [
      {
        "type": "domain",
        "value": "microsft-login.com",
        "risk_score": 95,
        "risk_label": "critical",
        "virus_total": {
          "reputation": "malicious",
          "malicious": 45,
          "permalink": "https://www.virustotal.com/gui/domain/microsft-login.com"
        },
        "whois": {
          "age_days": 2,
          "is_new_domain": true,
          "registrar": "NameCheap Inc.",
          "creation_date": "2025-01-15"
        }
      },
      {
        "type": "ip",
        "value": "185.220.101.1",
        "risk_score": 88,
        "risk_label": "high",
        "abuse_ipdb": {
          "abuse_score": 98,
          "total_reports": 247,
          "confidence": "high"
        },
        "shodan": {
          "open_ports": [22, 80, 443],
          "organization": "Tor Exit Node"
        }
      }
    ]
  }
}
```

## Benefits for SOC Analysts

✅ **No Manual Lookups** - Automatically checks VirusTotal, AbuseIPDB, Shodan, Whois  
✅ **Faster Triage** - Get enriched IOC data in seconds, not minutes  
✅ **Reduced Context Switching** - Stay in the SOC dashboard instead of opening 5 browser tabs  
✅ **Consistent Analysis** - Every email gets the same thorough IOC enrichment  
✅ **Actionable Recommendations** - Clear blocking/monitoring guidance  
✅ **Rate Limiting & Caching** - Respects API limits, avoids redundant queries  

## Rate Limits & Best Practices

| Service | Free Tier Limit | Cached For |
|---------|----------------|------------|
| VirusTotal | 4 req/min | 1 hour |
| AbuseIPDB | 1,000 req/day | 1 hour |
| Shodan | 100 queries/month | 1 hour |
| WhoisXML | 500 lookups/month | 1 hour |

**Tips:**
- Results are cached for 1 hour to minimize API usage
- Only unique IOCs are queried (duplicates skipped)
- System gracefully degrades if some APIs fail
- Consider paid tiers for high-volume SOC operations

## Troubleshooting

### "No external threat intel data available"
- Check that API keys are set in `.env`
- Verify API keys are valid (test in browser/API docs)
- Ensure outbound HTTPS access to API endpoints

### Slow response times
- First analysis of new IOCs takes longer (API calls)
- Subsequent analyses use cache (much faster)
- Check network connectivity to API endpoints

### API rate limit errors
- System automatically retries with exponential backoff
- Reduce concurrent email analysis volume
- Consider upgrading to paid API tier

## Architecture

```
Email Upload
    ↓
IOC Extraction (IPs, Domains, URLs, Hashes)
    ↓
┌───────────────────────────────────────┐
│  Parallel Threat Intel Queries        │
│  ├─ VirusTotal (Domain/IP/URL/Hash)   │
│  ├─ Whois Lookup (Domains)            │
│  ├─ AbuseIPDB (IPs)                   │
│  └─ Shodan (IPs)                      │
└───────────────────────────────────────┘
    ↓
Risk Scoring & Recommendation Engine
    ↓
Local LLM (Qwen2.5-14B) + TI Context
    ↓
Final Verdict + Actionable Guidance
```

## Files Modified/Added

- `/workspace/ai-soc-triage/src/threat_intel.py` - New threat intelligence module
- `/workspace/ai-soc-triage/src/api_server.py` - Updated `/email-analyze` endpoint
- `/workspace/ai-soc-triage/requirements.txt` - Added `requests` dependency
- `/workspace/ai-soc-triage/.env.example` - Added API key templates

## Next Steps

1. Get your free API keys from the services above
2. Add them to your `.env` file
3. Restart the backend server
4. Upload a phishing email and see automated threat intel in action!

For questions or issues, check the main SOC Sentinel documentation.
