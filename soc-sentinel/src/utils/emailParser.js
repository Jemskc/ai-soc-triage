let _idSeq = 1;
function nextId() { return `EM-${String(_idSeq++).padStart(4, '0')}`; }

// ── URL helpers ──────────────────────────────────────────────────────────────
const URL_SHORTENERS = ['bit.ly','tinyurl','t.co','goo.gl','ow.ly','buff.ly','short.io'];
const SUSPICIOUS_TLDS = ['.ru','.cn','.xyz','.tk','.top','.pw','.cc','.icu','.online','.site','.click'];
const SUSPICIOUS_KEYWORDS = ['login','verify','update','account','secure','confirm','reset','password','bank','paypal','amazon','microsoft','apple'];

function classifyUrl(url) {
  const lower = url.toLowerCase();
  const domain = (() => { try { return new URL(url).hostname; } catch { return ''; } })();
  if (URL_SHORTENERS.some(s => domain.includes(s))) return 'Shortened';
  if (SUSPICIOUS_TLDS.some(t => domain.endsWith(t))) return 'Suspicious';
  if (SUSPICIOUS_KEYWORDS.some(k => lower.includes(k))) return 'Suspicious';
  return 'External';
}

function classifyAttachment(filename) {
  const ext = (filename.split('.').pop() || '').toLowerCase();
  if (['exe','bat','cmd','ps1','vbs','js','jar','scr','com','pif','hta','msi'].includes(ext)) return 'CRITICAL';
  if (['zip','rar','7z','iso','img','tar','gz'].includes(ext)) return 'HIGH';
  if (['doc','docx','docm','xls','xlsx','xlsm','ppt','pptx','pptm'].includes(ext)) return 'MEDIUM';
  return 'LOW';
}

// ── Header parsing ────────────────────────────────────────────────────────────
function parseHeaders(block) {
  const headers = {};
  const lines = block.split(/\r?\n/);
  let currentKey = null;
  for (const line of lines) {
    if (/^\s+/.test(line) && currentKey) {
      headers[currentKey] += ' ' + line.trim();
    } else {
      const colon = line.indexOf(':');
      if (colon > 0) {
        currentKey = line.substring(0, colon).toLowerCase().trim();
        headers[currentKey] = line.substring(colon + 1).trim();
      }
    }
  }
  return headers;
}

// ── Auth result extraction ────────────────────────────────────────────────────
function extractAuth(headers) {
  const authStr = (headers['authentication-results'] || '').toLowerCase();
  const spfHdr  = (headers['received-spf'] || '').toLowerCase();

  const get = (str, key) => {
    const m = str.match(new RegExp(key + '\\s*=\\s*(pass|fail|none|neutral|softfail|temperror|permerror)'));
    if (!m) return 'none';
    const v = m[1];
    if (v === 'pass') return 'pass';
    if (['fail','softfail','permerror','temperror'].includes(v)) return 'fail';
    return 'none';
  };

  let spf = get(authStr, 'spf');
  if (spf === 'none' && spfHdr) {
    spf = spfHdr.startsWith('pass') ? 'pass' : spfHdr.startsWith('fail') || spfHdr.startsWith('softfail') ? 'fail' : 'none';
  }
  return { spf, dkim: get(authStr, 'dkim'), dmarc: get(authStr, 'dmarc') };
}

// ── Quoted-printable / base64 decode ─────────────────────────────────────────
function decodeQP(text) {
  return text
    .replace(/=\r\n/g, '').replace(/=\n/g, '')
    .replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}
function decodeB64(text) {
  try { return atob(text.replace(/\s/g, '')); } catch { return ''; }
}
function decodePart(content, encoding = '') {
  const enc = encoding.toLowerCase().trim();
  if (enc === 'quoted-printable') return decodeQP(content);
  if (enc === 'base64') return decodeB64(content);
  return content;
}

// ── URL extraction → {url, domain, risk}[] ───────────────────────────────────
function extractURLs(textPlain, textHtml) {
  const re = /https?:\/\/[^\s<>"')\]]+/gi;
  const raw = new Set([
    ...(textPlain.match(re) || []),
    ...(textHtml.match(re)  || []),
  ].map(u => u.replace(/[.,;]+$/, '')));
  return [...raw].map(url => {
    let domain = '';
    try { domain = new URL(url).hostname; } catch {}
    return { url, domain, risk: classifyUrl(url) };
  });
}

// ── Link-text mismatch detection ─────────────────────────────────────────────
function extractMismatches(html) {
  const mismatches = [];
  const re = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    const href = m[1];
    const inner = m[2].replace(/<[^>]+>/g, '').trim();
    if ((inner.includes('http') || /[\w-]+\.[a-z]{2,}/i.test(inner)) && inner !== href) {
      mismatches.push({ href, displayText: inner });
    }
  }
  return mismatches;
}

// ── MIME body extraction ──────────────────────────────────────────────────────
function extractBody(bodyBlock, contentType) {
  const lower = contentType.toLowerCase();
  const boundaryMatch = lower.match(/boundary="?([^";\r\n]+)"?/);

  let textPlain = '';
  let textHtml  = '';
  const attachments = [];

  if (boundaryMatch) {
    const boundary = '--' + boundaryMatch[1].trim();
    const escaped  = boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const parts    = bodyBlock.split(new RegExp(escaped));

    for (const part of parts) {
      const sep = part.search(/\r?\n\r?\n/);
      if (sep === -1) continue;
      const partHeaders = parseHeaders(part.slice(0, sep));
      const rawContent  = part.slice(sep + (part[sep] === '\r' ? 4 : 2)).trim();
      const ct          = (partHeaders['content-type'] || '').toLowerCase();
      const encoding    = partHeaders['content-transfer-encoding'] || '';
      const disposition = (partHeaders['content-disposition'] || '').toLowerCase();
      const decoded     = decodePart(rawContent, encoding);

      if (disposition.includes('attachment') || ct.includes('application/') || ct.includes('image/')) {
        const fnMatch = (partHeaders['content-disposition'] || partHeaders['content-type'] || '')
          .match(/filename\*?=(?:UTF-8'')?["']?([^"'\r\n;]+)/i);
        const filename = fnMatch ? fnMatch[1].trim().replace(/^["']|["']$/g, '') : 'attachment';
        attachments.push({
          filename,
          mimeType: ct.split(';')[0].trim(),
          encoding: encoding || 'none',
          size: Math.round(rawContent.length * 0.75),
          riskLevel: classifyAttachment(filename),
        });
      } else if (ct.includes('text/plain') && !textPlain) {
        textPlain = decoded;
      } else if (ct.includes('text/html') && !textHtml) {
        textHtml = decoded;
      }
    }
  } else {
    // Non-multipart
    const encoding = '';
    if (lower.includes('text/html')) {
      textHtml = bodyBlock;
    } else {
      textPlain = bodyBlock;
    }
  }

  return { textPlain, textHtml, attachments };
}

// ── Origin IP ─────────────────────────────────────────────────────────────────
function extractOriginIP(receivedHeaders) {
  const ipRe = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  const last  = receivedHeaders[receivedHeaders.length - 1] || '';
  const m     = last.match(ipRe);
  if (m) return m[0];
  // fall back scanning all
  for (const h of receivedHeaders) {
    const ips = h.match(ipRe);
    if (ips) return ips[0];
  }
  return '';
}

// ── Risk score ────────────────────────────────────────────────────────────────
const FREE_DOMAINS = ['gmail.com','yahoo.com','hotmail.com','outlook.com','protonmail.com','mail.com'];

function computeRisk(parsed) {
  let score = 0;
  if (parsed.spf   === 'fail') score += 30;
  if (parsed.dkim  === 'fail') score += 20;
  if (parsed.dmarc === 'fail') score += 15;
  for (const u of parsed.urls) {
    if (u.risk !== 'External') score += 10;
  }
  if (parsed.replyTo) {
    try {
      const fd = parsed.from.match(/@([\w.-]+)/)?.[1] || '';
      const rd = parsed.replyTo.match(/@([\w.-]+)/)?.[1] || '';
      if (fd && rd && fd !== rd) score += 20;
    } catch {}
  }
  const fromDomain = parsed.from.match(/@([\w.-]+)/)?.[1] || '';
  if (FREE_DOMAINS.includes(fromDomain)) score += 10;
  score += parsed.attachments.length * 5;
  return Math.min(100, score);
}

function riskLabel(score) {
  if (score >= 86) return 'Critical';
  if (score >= 61) return 'High';
  if (score >= 31) return 'Medium';
  return 'Low';
}

// ── Main export ───────────────────────────────────────────────────────────────
export function parseEmlFile(rawText) {
  const crlf   = rawText.indexOf('\r\n\r\n');
  const lf     = rawText.indexOf('\n\n');
  const sep    = crlf !== -1 ? crlf : lf;
  if (sep === -1) return null;

  const headerBlock = rawText.substring(0, sep);
  const bodyBlock   = rawText.substring(sep + (crlf !== -1 ? 4 : 2));
  const headers     = parseHeaders(headerBlock);

  const allReceivedHeaders = (headerBlock.match(/^Received:.*(?:\n[ \t].*)*/gmi) || [])
    .map(h => h.replace(/^Received:\s*/i, '').replace(/\n[ \t]+/g, ' ').trim());

  const originIP    = extractOriginIP(allReceivedHeaders);
  const { spf, dkim, dmarc } = extractAuth(headers);
  const contentType = headers['content-type'] || 'text/plain';
  const { textPlain, textHtml, attachments } = extractBody(bodyBlock, contentType);
  const urls      = extractURLs(textPlain, textHtml);
  const domains   = [...new Set(urls.map(u => u.domain).filter(Boolean))];
  const mismatches = textHtml ? extractMismatches(textHtml) : [];

  const parsed = {
    id: nextId(),
    subject:          headers['subject'] || '(No Subject)',
    from:             headers['from'] || '',
    to:               headers['to'] || '',
    date:             headers['date'] || '',
    replyTo:          headers['reply-to'] || '',
    messageId:        headers['message-id'] || '',
    xMailer:          headers['x-mailer'] || headers['user-agent'] || '',
    contentType:      headers['content-type'] || '',
    mimeVersion:      headers['mime-version'] || '',
    xSpamStatus:      headers['x-spam-status'] || '',
    xSpamScore:       headers['x-spam-score'] || '',
    xOriginatingIp:   headers['x-originating-ip'] || '',
    authResults:      headers['authentication-results'] || '',
    receivedSpf:      headers['received-spf'] || '',
    dkimSignature:    headers['dkim-signature'] ? headers['dkim-signature'].slice(0, 60) + '…' : '',
    listUnsubscribe:  headers['list-unsubscribe'] || '',
    allReceivedHeaders,
    originIP,
    spf, dkim, dmarc,
    bodyText:  textPlain,
    bodyHtml:  textHtml,
    urls,       // [{url, domain, risk}]
    domains,
    attachments, // [{filename, mimeType, size, riskLevel}]
    mismatches,
    riskScore: 0,
    riskLabel: 'Low',
    status: 'Unreviewed',
    _raw: rawText,
  };

  parsed.riskScore = computeRisk(parsed);
  parsed.riskLabel = riskLabel(parsed.riskScore);
  return parsed;
}

// Legacy string constants kept for backward compat
export const DANGEROUS_EXTS = ['.exe','.js','.vbs','.ps1','.bat','.cmd','.scr','.pif','.hta'];
export const SUSPICIOUS_URL_PATTERNS = ['bit.ly','tinyurl','.ru/','.xyz/','.tk/','login','verify','update','account','secure','signin','password','confirm'];
