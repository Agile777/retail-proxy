console.error('This folder is deprecated.');
console.error('Use the repo-root server.js for local + Render deployments.');
process.exit(1);

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

// SMS Portal API Proxy - Updated with new credentials and endpoints
app.all('/api/sms/*', async (req, res) => {
  try {
    const secrets = loadLocalSecrets();
    const clientId = process.env.SMS_CLIENT_ID || secrets?.SMS_CLIENT_ID || 'b0839bcb-89e2-4592-8cf8-3a265c1cc82f';
    const clientSecret = process.env.SMS_CLIENT_SECRET || secrets?.SMS_CLIENT_SECRET || '3OVb1yFZdskv/YJfHZW1VBeQjH4yzfpC';

    if (!clientId || !clientSecret) {
      return res.status(400).json({
        ok: false,
        error: 'Missing SMS credentials'
      });
    }

    // Extract the path after /api/sms/
    const smsPath = req.url.replace('/api/sms', '');
    const smsUrl = `https://rest.smsportal.com${smsPath}`;

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
});

// Listen on 0.0.0.0 for Render.com compatibility
const host = process.env.RENDER ? '0.0.0.0' : '127.0.0.1';
app.listen(PORT, host, () => {
  console.log(`[rs-local-proxy] listening on http://${host}:${PORT}`);
  console.log(`[rs-local-proxy] health: http://${host}:${PORT}/health`);
  console.log(`[rs-local-proxy] Environment: ${process.env.RENDER ? 'Render.com' : 'Local'}`);
});
