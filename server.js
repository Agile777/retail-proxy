import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = process.env.PORT ? Number(process.env.PORT) : 3001;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

function loadLocalSecrets(){
  try {
    const candidates = [
      path.join(process.cwd(), 'secrets.local.json'),
      path.join(__dirname, 'secrets.local.json')
    ];
    const filePath = candidates.find(p => fs.existsSync(p));
    if (!filePath) return null;

    const raw = fs.readFileSync(filePath, 'utf-8');
    const json = JSON.parse(raw);
    return json && typeof json === 'object' ? json : null;
  } catch (_) {
    return null;
  }
}

function cdataWrap(value) {
  const s = String(value ?? '');
  // Safely split any occurrence of ']]>'
  const safe = s.replaceAll(']]>', ']]]]><![CDATA[>');
  return `<![CDATA[${safe}]]>`;
}

function extractTagText(xml, tagName) {
  if (!xml) return null;
  const re = new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)</${tagName}>`, 'i');
  const m = xml.match(re);
  return m ? m[1] : null;
}

function extractRequestKey(text) {
  if (!text) return null;
  // Common patterns seen in vendor XML payloads
  const patterns = [
    /<RequestKey>([^<]+)<\/RequestKey>/i,
    /RequestKey\s*=\s*"([^"]+)"/i,
    /RequestKey\s*:\s*([A-Za-z0-9_-]+)/i
  ];
  for (const re of patterns) {
    const m = String(text).match(re);
    if (m && m[1]) return m[1].trim();
  }
  return null;
}

app.get('/health', (req, res) => {
  const secrets = loadLocalSecrets();
  res.json({
    ok: true,
    service: 'rs-local-proxy',
    port: PORT,
    time: new Date().toISOString(),
    cwd: process.cwd(),
    secretsFileDetected: Boolean(secrets),
    envVariablesDetected: {
      MIE_PASSWORD: !!process.env.MIE_PASSWORD,
      MIE_USERNAME: !!process.env.MIE_USERNAME,
      SMS_CLIENT_SECRET: !!process.env.SMS_CLIENT_SECRET
    }
  });
});

// MIE proxy endpoint
app.post('/api/mie', async (req, res) => {
  try {
    const {
      method,
      soapUrl,
      username,
      password: passwordFromBody,
      clientKey,
      agentKey,
      source,
      payload = {},
      aLogonXml: aLogonXmlOverride,
      aArgument: aArgumentOverride
    } = req.body || {};

    if (!method) return res.status(400).json({ ok: false, error: 'Missing method' });
    if (!soapUrl) return res.status(400).json({ ok: false, error: 'Missing soapUrl' });

    const secrets = loadLocalSecrets();
    const password = passwordFromBody || process.env.MIE_PASSWORD || secrets?.MIE_PASSWORD || secrets?.mie_password || null;
    if (!password) {
      return res.status(400).json({
        ok: false,
        error: 'Missing MIE password',
        hint: 'Set MIE_PASSWORD as an environment variable OR add secrets.local.json with { "MIE_PASSWORD": "..." }'
      });
    }

    // aLogonXml - MIE's EXACT format from their SOAP UI documentation
    const aLogonXml = aLogonXmlOverride || 
      `<xml><Token>` +
      `<UserName>${username ?? ''}</UserName>` +
      `<Password>${password}</Password>` +
      `<Source>${source ?? ''}</Source>` +
      `</Token></xml>`;

    // aArgument - MIE's EXACT Request format from their documentation
    const checkTypes = Array.isArray(payload.checkTypes) ? payload.checkTypes : [];
    const remoteKey = payload.remoteKey || `RS_${Date.now()}`;
    const currentDate = new Date().toISOString();
    
    // Log indemnity status for debugging
    console.log('🔍 Building MIE Request - indemnityAcknowledged:', payload.indemnityAcknowledged);
    
    const aArgument = aArgumentOverride || 
      `<xml><Request>` +
      `<ClientKey>${clientKey ?? ''}</ClientKey>` +
      `<AgentClient>${clientKey ?? ''}</AgentClient>` +
      `<AgentKey>${agentKey ?? ''}</AgentKey>` +
      `<RemoteRequest>${remoteKey}</RemoteRequest>` +
      `<OrderNumber></OrderNumber>` +
      `<RequestReason></RequestReason>` +
      `<Note></Note>` +
      `<FirstNames>${payload.firstName ?? ''}</FirstNames>` +
      `<Surname>${payload.lastName ?? ''}</Surname>` +
      `<MaidenName></MaidenName>` +
      `<IdNumber>${payload.idNumber ?? ''}</IdNumber>` +
      `<Passport></Passport>` +
      (payload.dateOfBirth ? `<DateOfBirth>${payload.dateOfBirth}</DateOfBirth>` : '<DateOfBirth></DateOfBirth>') +
      `<ContactNumber>${payload.phone ?? ''}</ContactNumber>` +
      `<PersonEmail>${payload.email ?? ''}</PersonEmail>` +
      `<AlternateEmail></AlternateEmail>` +
      `<Source>${payload.source ?? source ?? ''}</Source>` +
      `<EntityKind>P</EntityKind>` +
      `<RemoteCaptureDate>${currentDate}</RemoteCaptureDate>` +
      `<RemoteSendDate>${currentDate}</RemoteSendDate>` +
      `<RemoteGroup></RemoteGroup>` +
      `<PrerequisiteGroupList></PrerequisiteGroupList>` +
      `<PrerequisiteImageList></PrerequisiteImageList>` +
      `<ItemList>` +
      checkTypes.map(t => 
        `<Item>` +
        `<RemoteItemKey></RemoteItemKey>` +
        `<ItemTypeCode>${t.toUpperCase()}</ItemTypeCode>` +
        `<Indemnity>${payload.indemnityAcknowledged ? 'true' : 'false'}</Indemnity>` +
        `<ItemInputGroupList></ItemInputGroupList>` +
        `</Item>`
      ).join('') +
      `</ItemList>` +
      `</Request></xml>`;

    const hasArgument = ['ksoputrequest', 'ksoputbranch', 'ksoputrequestredirect'].includes(String(method).toLowerCase());

    const soapEnvelope = `<?xml version="1.0" encoding="utf-8"?>\n` +
      `<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
      `<soap:Body>` +
      `<${method} xmlns="http://www.kroll.co.za/">` +
      `<aLogonXml>${cdataWrap(aLogonXml)}</aLogonXml>` +
      (hasArgument ? `<aArgument>${cdataWrap(aArgument)}</aArgument>` : '') +
      `</${method}>` +
      `</soap:Body>` +
      `</soap:Envelope>`;

    const soapAction = `http://www.kroll.co.za/${method}`;

    const resp = await fetch(soapUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': soapAction,
        'Accept': 'text/xml'
      },
      body: soapEnvelope
    });

    const respText = await resp.text();

    if (!resp.ok) {
      return res.status(502).json({
        ok: false,
        error: `MIE SOAP HTTP ${resp.status}`,
        soapAction,
        soapUrl,
        responseSnippet: respText.slice(0, 2000)
      });
    }

    const resultTag = `${method}Result`;
    const resultText = extractTagText(respText, resultTag);
    const requestKey = extractRequestKey(resultText);

    return res.json({
      ok: true,
      method,
      soapAction,
      requestKey: requestKey || null,
      reference: requestKey || null,
      result: resultText || null,
      rawSoapResponse: respText
    });
  } catch (err) {
    console.error('MIE proxy error:', err);
    return res.status(500).json({ ok: false, error: err?.message || String(err) });
  }
});

function getSmsCredentials() {
  const secrets = loadLocalSecrets();
  const clientId = process.env.SMS_CLIENT_ID || secrets?.SMS_CLIENT_ID || secrets?.sms_client_id || null;
  const clientSecret = process.env.SMS_CLIENT_SECRET || secrets?.SMS_CLIENT_SECRET || secrets?.sms_client_secret || null;
  return { clientId, clientSecret };
}

function formatSmsPortalNumber(phone) {
  if (!phone) return '';
  let cleaned = String(phone).replace(/\D/g, '');
  if (!cleaned) return '';
  // Normalize to 27XXXXXXXXX (no +)
  if (cleaned.startsWith('27')) return cleaned;
  if (cleaned.startsWith('0')) return `27${cleaned.slice(1)}`;
  if (cleaned.length === 9) return `27${cleaned}`;
  return cleaned;
}

async function forwardSms(req, res, smsPathOverride = null) {
  try {
    const { clientId, clientSecret } = getSmsCredentials();

    if (!clientId || !clientSecret) {
      return res.status(400).json({
        ok: false,
        error: 'Missing SMS credentials',
        hint: 'Set SMS_CLIENT_ID and SMS_CLIENT_SECRET as Render environment variables (or secrets.local.json for local dev).'
      });
    }

    // Extract the path after /api/sms
    const smsPath = smsPathOverride !== null
      ? smsPathOverride
      : req.url.replace('/api/sms', '');
    const smsUrl = `https://rest.smsportal.com${smsPath || ''}`;

    console.log('SMS Proxy Request:', {
      method: req.method,
      url: smsUrl,
      hasAuth: true
    });

    // Create base64 auth header
    const authString = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    // Forward request to SMS Portal API with authentication
    const response = await fetch(smsUrl, {
      method: req.method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${authString}`
      },
      body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined
    });

    const contentType = response.headers.get('content-type');
    
    // Handle JSON responses
    if (contentType && contentType.includes('application/json')) {
      const data = await response.json();
      return res.status(response.status).json(data);
    }
    
    // Handle text responses
    const text = await response.text();
    return res.status(response.status).send(text);

  } catch (err) {
    console.error('SMS proxy error:', err);
    return res.status(500).json({ 
      ok: false, 
      error: err?.message || String(err),
      stack: err?.stack 
    });
  }
}

// Friendly endpoints used by the front-end
app.post('/api/sms/send', async (req, res) => {
  try {
    const { message, recipients, options = {} } = req.body || {};
    if (!message || !String(message).trim()) {
      return res.status(400).json({ success: false, error: 'Message cannot be empty' });
    }
    if (!Array.isArray(recipients) || recipients.length === 0) {
      return res.status(400).json({ success: false, error: 'No recipients specified' });
    }

    const messages = recipients.map(r => {
      const raw = (r && typeof r === 'object') ? (r.cellphone_number || r.phone || r.contact_number || r.mobile) : r;
      const destination = formatSmsPortalNumber(raw);
      return {
        content: String(message).trim(),
        destination,
        ...(options.scheduledFor ? { sendTime: options.scheduledFor } : {}),
        ...(options.reference ? { reference: options.reference } : {})
      };
    }).filter(m => m.destination);

    if (!messages.length) {
      return res.status(400).json({ success: false, error: 'No valid recipient numbers found' });
    }

    // SMS Portal bulk send
    const payload = {
      messages,
      testMode: !!options.testMode,
      ...(options.senderId ? { senderId: options.senderId } : {})
    };

    // Forward to the vendor endpoint
    // Note: SMSPortal uses /BulkMessages for bulk sends.
    const reqClone = {
      ...req,
      method: 'POST',
      body: payload
    };
    const forwardRes = await (async () => {
      // reuse the forwarding logic but override the path
      return forwardSms(reqClone, res, '/BulkMessages');
    })();
    return forwardRes;
  } catch (err) {
    console.error('SMS send error:', err);
    return res.status(500).json({ success: false, error: err?.message || String(err), type: 'proxy_error' });
  }
});

app.get('/api/sms/test', async (req, res) => {
  // Simple connectivity check used by sms-api.js
  return forwardSms(req, res, '/v1/Balance');
});

// Generic forwarders (supports /api/sms and /api/sms/*)
app.all('/api/sms', (req, res) => forwardSms(req, res));
app.all('/api/sms/*', (req, res) => forwardSms(req, res));

// Listen on 0.0.0.0 for Render.com compatibility (safe for local too)
const host = '0.0.0.0';
app.listen(PORT, host, () => {
  console.log(`[rs-local-proxy] listening on http://${host}:${PORT}`);
  console.log(`[rs-local-proxy] health: http://${host}:${PORT}/health`);
  console.log(`[rs-local-proxy] Environment: ${process.env.RENDER ? 'Render.com' : 'Local'}`);
});
