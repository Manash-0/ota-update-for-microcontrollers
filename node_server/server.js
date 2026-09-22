/**
 * ══════════════════════════════════════════════════════════════
 *  NODE.JS FIRMWARE UPDATE SERVER
 *  Serves SUIT manifests + firmware images for ESP8266 OTA
 * ══════════════════════════════════════════════════════════════
 *
 *  Zero dependencies — uses only built-in Node.js modules.
 *
 *  NORMAL Endpoints:
 *    GET /              → Status dashboard (HTML)
 *    GET /fw/manifest   → SUIT manifest binary (valid)
 *    GET /fw/image      → Firmware image binary (valid)
 *
 *  EDGE-CASE TEST Endpoints:
 *    GET /fw/manifest/corrupt   → Manifest with WRONG SHA-256 hash
 *    GET /fw/manifest/rollback  → Manifest with seq=0 (old version)
 *    GET /fw/manifest/unsigned  → Manifest with zeroed signature
 *    GET /fw/manifest/badmagic  → Manifest with invalid magic bytes
 *    GET /fw/image/tampered     → Firmware with one byte flipped
 *    GET /fw/manifest/unauth    → Manifest served only if X-Device-ID matches
 *
 *  Usage:
 *    node server.js                    → Serve with auto-generated test data
 *    node server.js --bin firmware.bin → Serve a real .bin firmware file
 *    node server.js --port 3000       → Change port (default: 8080)
 *    node server.js --seq 5           → Set firmware version/sequence number
 *
 *  Setup:
 *    1. Connect your laptop to your mobile hotspot
 *    2. Find your laptop's IP: ipconfig (look for Wireless LAN adapter)
 *    3. Run: node server.js
 *    4. Put that IP into the ESP8266 sketch
 *    5. Upload sketch to NodeMCU, open Serial Monitor
 * ══════════════════════════════════════════════════════════════
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ── CLI Arguments ─────────────────────────────────────────────
const args = process.argv.slice(2);
function getArg(name, defaultVal) {
    const idx = args.indexOf(name);
    return idx !== -1 && args[idx + 1] ? args[idx + 1] : defaultVal;
}

const PORT = parseInt(getArg('--port', '8082'));
const SEQ_NUM = parseInt(getArg('--seq', '2'));
const BIN_FILE = getArg('--bin', null);

/* Authorized device ID for host validation test */
const AUTHORIZED_DEVICE_ID = 'NODEMCU-ESP12E-001';

// ── Firmware Data ─────────────────────────────────────────────
let firmwareData = null;
let firmwareHash = null;
let manifestData = null;
let firmwareSize = 0;

/* Edge-case data (built in initData) */
let manifestCorrupt = null;   // wrong hash
let manifestRollback = null;  // seq = 0
let manifestUnsigned = null;  // zeroed signature
let manifestBadMagic = null;  // invalid magic bytes
let firmwareTampered = null;  // one byte flipped

// ── SUIT Manifest Builder ─────────────────────────────────────
// Simplified binary format (big-endian), matches the ESP8266 parser:
//   [4B magic "SUIT"] [4B seq] [4B fw_size] [1B format]
//   [1B uri_len] [N uri] [32B sha256] [64B ed25519_sig]

function writeBE32(buf, offset, val) {
    buf[offset]     = (val >> 24) & 0xFF;
    buf[offset + 1] = (val >> 16) & 0xFF;
    buf[offset + 2] = (val >> 8)  & 0xFF;
    buf[offset + 3] = val & 0xFF;
}

function buildManifest(fwHash, fwSize, seqNum, opts = {}) {
    const uri = opts.uri || '/fw/image';
    const uriBytes = Buffer.from(uri, 'ascii');
    const totalSize = 4 + 4 + 4 + 1 + 1 + uriBytes.length + 32 + 64;
    const buf = Buffer.alloc(totalSize);

    let off = 0;

    // Magic: "SUIT" = 0x53554954 (or custom for badmagic test)
    const magic = opts.badMagic ? 0xDEADBEEF : 0x53554954;
    writeBE32(buf, off, magic); off += 4;

    // Sequence number
    writeBE32(buf, off, seqNum); off += 4;

    // Firmware size
    writeBE32(buf, off, fwSize); off += 4;

    // Format type: 0x01 = raw binary
    buf[off++] = 0x01;

    // URI length + URI
    buf[off++] = uriBytes.length;
    uriBytes.copy(buf, off); off += uriBytes.length;

    // SHA-256 digest
    fwHash.copy(buf, off); off += 32;

    // ed25519 signature
    if (opts.zeroSignature) {
        buf.fill(0x00, off, off + 64);  // all zeros = INVALID
    } else {
        buf.fill(0x01, off, off + 64);  // non-zero = valid (stub)
    }
    off += 64;

    return buf;
}

// ── Generate Test Firmware ────────────────────────────────────
function generateTestFirmware(size = 4096) {
    console.log(`\n[BUILD] Generating test firmware (${size} bytes, seq=${SEQ_NUM})...`);

    const fw = Buffer.alloc(size);
    for (let i = 0; i < size; i++) {
        fw[i] = (i * 7 + 13) & 0xFF;
    }

    // Add fake Cortex-M vector table header
    fw[0] = 0x00; fw[1] = 0x20; fw[2] = 0x00; fw[3] = 0x00;
    fw[4] = 0x00; fw[5] = 0x08; fw[6] = 0x00; fw[7] = 0x99;

    return fw;
}

// ── Initialize Data ───────────────────────────────────────────
function initData() {
    if (BIN_FILE) {
        // Load real firmware binary
        const filePath = path.resolve(BIN_FILE);
        if (!fs.existsSync(filePath)) {
            console.error(`[ERROR] File not found: ${filePath}`);
            process.exit(1);
        }
        firmwareData = fs.readFileSync(filePath);
        console.log(`[LOAD] Loaded firmware: ${filePath} (${firmwareData.length} bytes)`);
    } else {
        // Generate test firmware
        firmwareData = generateTestFirmware(4096);
    }

    firmwareSize = firmwareData.length;

    // Compute SHA-256
    firmwareHash = crypto.createHash('sha256').update(firmwareData).digest();
    console.log(`[BUILD] SHA-256: ${firmwareHash.toString('hex')}`);

    // ─── Build VALID SUIT manifest ────────────────────────────
    manifestData = buildManifest(firmwareHash, firmwareSize, SEQ_NUM);
    console.log(`[BUILD] Manifest: ${manifestData.length} bytes`);
    console.log(`[BUILD] Firmware: ${firmwareSize} bytes, version ${SEQ_NUM}`);

    // ─── Build EDGE-CASE manifests ────────────────────────────

    // 1. Corrupt hash: replace real hash with random bytes
    const fakeHash = crypto.randomBytes(32);
    manifestCorrupt = buildManifest(fakeHash, firmwareSize, SEQ_NUM);
    console.log(`[EDGE] Built corrupt-hash manifest (wrong SHA-256)`);

    // 2. Rollback: seq = 0 (older than any installed firmware)
    manifestRollback = buildManifest(firmwareHash, firmwareSize, 0);
    console.log(`[EDGE] Built rollback manifest (seq=0)`);

    // 3. Unsigned: signature bytes all zero
    manifestUnsigned = buildManifest(firmwareHash, firmwareSize, SEQ_NUM,
                                     { zeroSignature: true });
    console.log(`[EDGE] Built unsigned manifest (zeroed signature)`);

    // 4. Bad magic: magic = 0xDEADBEEF instead of "SUIT"
    manifestBadMagic = buildManifest(firmwareHash, firmwareSize, SEQ_NUM,
                                     { badMagic: true });
    console.log(`[EDGE] Built bad-magic manifest (0xDEADBEEF)`);

    // 5. Tampered firmware: flip one byte
    firmwareTampered = Buffer.from(firmwareData);
    firmwareTampered[Math.floor(firmwareTampered.length / 2)] ^= 0xFF;
    const tamperedHash = crypto.createHash('sha256').update(firmwareTampered).digest();
    console.log(`[EDGE] Built tampered firmware (byte ${Math.floor(firmwareTampered.length / 2)} flipped)`);
    console.log(`[EDGE] Tampered SHA-256: ${tamperedHash.toString('hex').substring(0, 32)}...`);
}

// ── Statistics ────────────────────────────────────────────────
let stats = {
    manifestDownloads: 0,
    firmwareDownloads: 0,
    edgeCaseTests: 0,
    rejectedUnauth: 0,
    startTime: Date.now()
};

// ── Get Local IP Addresses ────────────────────────────────────
function getLocalIPs() {
    const interfaces = os.networkInterfaces();
    const ips = [];
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                ips.push({ name, address: iface.address });
            }
        }
    }
    return ips;
}

// ── HTML Dashboard ────────────────────────────────────────────
function statusPage() {
    const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
    const ips = getLocalIPs();
    const ipList = ips.map(ip =>
        `<div class="stat"><span class="label">${ip.name}</span><span class="value">${ip.address}</span></div>`
    ).join('\n');

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Firmware Update Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0a0e17, #1a1f35);
            color: #e0e0e0; min-height: 100vh; padding: 20px;
        }
        .container { max-width: 700px; margin: 0 auto; }
        .card {
            background: linear-gradient(135deg, #1a1f2e, #252b3d);
            border: 1px solid #2d3548; border-radius: 16px;
            padding: 24px; margin-bottom: 16px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        h1 { color: #6c9fff; text-align: center; font-size: 1.4em; margin-bottom: 4px; }
        h2 { color: #9ca3af; font-size: 1em; border-bottom: 1px solid #2d3548;
            padding-bottom: 8px; margin-bottom: 12px; }
        .subtitle { text-align: center; color: #9ca3af; margin-bottom: 0; }
        .stat { display: flex; justify-content: space-between; padding: 8px 0;
            border-bottom: 1px solid #1a1f2e; }
        .label { color: #9ca3af; }
        .value { color: #6c9fff; font-weight: 600; }
        .ok { color: #34d399; }
        .warn { color: #fbbf24; }
        .fail { color: #f87171; }
        .hash { font-family: 'Courier New', monospace; font-size: 0.72em;
            word-break: break-all; color: #fbbf24; background: #0d1117;
            padding: 10px; border-radius: 8px; margin-top: 8px; line-height: 1.6; }
        .badge { background: #1e3a5f; color: #6c9fff; padding: 2px 10px;
            border-radius: 12px; font-size: 0.85em; }
        .badge-warn { background: #3f2e1e; color: #fbbf24; padding: 2px 10px;
            border-radius: 12px; font-size: 0.85em; }
        a { color: #6c9fff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .refresh { text-align: center; margin-top: 12px; }
        .refresh a { background: #1e3a5f; padding: 8px 20px; border-radius: 8px; }
        .edge-desc { font-size: 0.82em; color: #9ca3af; margin-top: 2px; }
    </style>
    <meta http-equiv="refresh" content="10">
</head>
<body>
<div class="container">
    <div class="card">
        <h1>🔒 Secure IoT Firmware Update Server</h1>
        <p class="subtitle">Node.js • SUIT-OTA Protocol • ESP8266 OTA</p>
    </div>

    <div class="card">
        <h2>📦 Firmware Info</h2>
        <div class="stat"><span class="label">Version (seq)</span>
            <span class="value">${SEQ_NUM}</span></div>
        <div class="stat"><span class="label">Size</span>
            <span class="value">${firmwareSize.toLocaleString()} bytes</span></div>
        <div class="stat"><span class="label">Manifest</span>
            <span class="value">${manifestData.length} bytes</span></div>
        <div class="stat"><span class="label">Source</span>
            <span class="badge">${BIN_FILE ? path.basename(BIN_FILE) : 'Auto-generated'}</span></div>
        <div class="stat"><span class="label">Status</span>
            <span class="ok">● Ready</span></div>
        <p style="color:#9ca3af; margin-top:12px; margin-bottom:4px;">SHA-256:</p>
        <div class="hash">${firmwareHash.toString('hex')}</div>
    </div>

    <div class="card">
        <h2>🌐 Your Network IPs</h2>
        ${ipList}
        <p style="color:#6c9fff; margin-top:12px; font-size:0.85em;">
            👆 Use one of these IPs in your ESP8266 sketch</p>
    </div>

    <div class="card">
        <h2>📡 Normal Endpoints</h2>
        <div class="stat"><span class="label">Manifest</span>
            <span class="value"><a href="/fw/manifest">GET /fw/manifest</a></span></div>
        <div class="stat"><span class="label">Firmware</span>
            <span class="value"><a href="/fw/image">GET /fw/image</a></span></div>
    </div>

    <div class="card">
        <h2>🧪 Edge-Case Test Endpoints</h2>
        <div class="stat"><span class="label">Corrupt Hash</span>
            <span class="badge-warn"><a href="/fw/manifest/corrupt" style="color:#fbbf24">/fw/manifest/corrupt</a></span></div>
        <p class="edge-desc">→ Manifest with wrong SHA-256 → client should reject at hash check</p>

        <div class="stat"><span class="label">Rollback</span>
            <span class="badge-warn"><a href="/fw/manifest/rollback" style="color:#fbbf24">/fw/manifest/rollback</a></span></div>
        <p class="edge-desc">→ Manifest with seq=0 → client should reject at anti-rollback</p>

        <div class="stat"><span class="label">Unsigned</span>
            <span class="badge-warn"><a href="/fw/manifest/unsigned" style="color:#fbbf24">/fw/manifest/unsigned</a></span></div>
        <p class="edge-desc">→ Manifest with zeroed signature → client should reject at verification</p>

        <div class="stat"><span class="label">Bad Magic</span>
            <span class="badge-warn"><a href="/fw/manifest/badmagic" style="color:#fbbf24">/fw/manifest/badmagic</a></span></div>
        <p class="edge-desc">→ Invalid magic bytes → client should reject at parsing</p>

        <div class="stat"><span class="label">Tampered FW</span>
            <span class="badge-warn"><a href="/fw/image/tampered" style="color:#fbbf24">/fw/image/tampered</a></span></div>
        <p class="edge-desc">→ Firmware with flipped byte → hash mismatch after download</p>

        <div class="stat"><span class="label">Unauth Device</span>
            <span class="badge-warn"><a href="/fw/manifest/unauth" style="color:#fbbf24">/fw/manifest/unauth</a></span></div>
        <p class="edge-desc">→ Requires X-Device-ID header → rejects unauthorized clients</p>
    </div>

    <div class="card">
        <h2>📊 Statistics</h2>
        <div class="stat"><span class="label">Manifest downloads</span>
            <span class="value">${stats.manifestDownloads}</span></div>
        <div class="stat"><span class="label">Firmware downloads</span>
            <span class="value">${stats.firmwareDownloads}</span></div>
        <div class="stat"><span class="label">Edge-case tests served</span>
            <span class="warn">${stats.edgeCaseTests}</span></div>
        <div class="stat"><span class="label">Unauthorized rejections</span>
            <span class="fail">${stats.rejectedUnauth}</span></div>
        <div class="stat"><span class="label">Uptime</span>
            <span class="value">${uptime}s</span></div>
    </div>

    <div class="refresh"><a href="/">↻ Refresh</a></div>
</div>
</body>
</html>`;
}

// ── HTTP Server ───────────────────────────────────────────────
const server = http.createServer((req, res) => {
    const clientIP = req.socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
    const timestamp = new Date().toLocaleTimeString();

    /* ── Normal endpoints ──────────────────────────────────── */

    if (req.method === 'GET' && req.url === '/') {
        const html = statusPage();
        res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': Buffer.byteLength(html)
        });
        res.end(html);
        console.log(`[${timestamp}] ${clientIP} → GET / (dashboard)`);

    } else if (req.method === 'GET' && req.url === '/fw/manifest') {
        stats.manifestDownloads++;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': manifestData.length,
            'X-Firmware-Version': SEQ_NUM.toString(),
            'X-Firmware-Size': firmwareSize.toString()
        });
        res.end(manifestData);
        console.log(`[${timestamp}] ${clientIP} → GET /fw/manifest ✓ (${manifestData.length} bytes) [#${stats.manifestDownloads}]`);

    } else if (req.method === 'GET' && req.url === '/fw/image') {
        stats.firmwareDownloads++;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': firmwareSize,
            'X-Content-SHA256': firmwareHash.toString('hex')
        });
        res.end(firmwareData);
        console.log(`[${timestamp}] ${clientIP} → GET /fw/image ✓ (${firmwareSize} bytes) [#${stats.firmwareDownloads}]`);

    /* ── Edge-case test endpoints ──────────────────────────── */

    } else if (req.method === 'GET' && req.url === '/fw/manifest/corrupt') {
        stats.edgeCaseTests++;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': manifestCorrupt.length
        });
        res.end(manifestCorrupt);
        console.log(`[${timestamp}] ${clientIP} → GET /fw/manifest/corrupt ⚠ CORRUPT HASH [#${stats.edgeCaseTests}]`);

    } else if (req.method === 'GET' && req.url === '/fw/manifest/rollback') {
        stats.edgeCaseTests++;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': manifestRollback.length
        });
        res.end(manifestRollback);
        console.log(`[${timestamp}] ${clientIP} → GET /fw/manifest/rollback ⚠ SEQ=0 ROLLBACK [#${stats.edgeCaseTests}]`);

    } else if (req.method === 'GET' && req.url === '/fw/manifest/unsigned') {
        stats.edgeCaseTests++;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': manifestUnsigned.length
        });
        res.end(manifestUnsigned);
        console.log(`[${timestamp}] ${clientIP} → GET /fw/manifest/unsigned ⚠ ZERO SIGNATURE [#${stats.edgeCaseTests}]`);

    } else if (req.method === 'GET' && req.url === '/fw/manifest/badmagic') {
        stats.edgeCaseTests++;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': manifestBadMagic.length
        });
        res.end(manifestBadMagic);
        console.log(`[${timestamp}] ${clientIP} → GET /fw/manifest/badmagic ⚠ BAD MAGIC 0xDEADBEEF [#${stats.edgeCaseTests}]`);

    } else if (req.method === 'GET' && req.url === '/fw/image/tampered') {
        stats.edgeCaseTests++;
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': firmwareTampered.length
        });
        res.end(firmwareTampered);
        console.log(`[${timestamp}] ${clientIP} → GET /fw/image/tampered ⚠ TAMPERED FIRMWARE [#${stats.edgeCaseTests}]`);

    } else if (req.method === 'GET' && req.url === '/fw/manifest/unauth') {
        const deviceId = req.headers['x-device-id'];
        if (deviceId === AUTHORIZED_DEVICE_ID) {
            stats.edgeCaseTests++;
            res.writeHead(200, {
                'Content-Type': 'application/octet-stream',
                'Content-Length': manifestData.length
            });
            res.end(manifestData);
            console.log(`[${timestamp}] ${clientIP} → GET /fw/manifest/unauth ✓ AUTHORIZED (ID: ${deviceId})`);
        } else {
            stats.rejectedUnauth++;
            res.writeHead(403, { 'Content-Type': 'text/plain' });
            res.end('403 Forbidden — Unauthorized device\n');
            console.log(`[${timestamp}] ${clientIP} → GET /fw/manifest/unauth ✗ REJECTED (ID: ${deviceId || 'MISSING'})`);
        }

    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found\n\nEndpoints:\n  GET /                    - Dashboard\n  GET /fw/manifest         - SUIT manifest (valid)\n  GET /fw/image            - Firmware binary (valid)\n  GET /fw/manifest/corrupt - Corrupt hash test\n  GET /fw/manifest/rollback- Rollback test (seq=0)\n  GET /fw/manifest/unsigned- Unsigned manifest test\n  GET /fw/manifest/badmagic- Bad magic bytes test\n  GET /fw/image/tampered   - Tampered firmware test\n  GET /fw/manifest/unauth  - Auth check (needs X-Device-ID)\n');
        console.log(`[${timestamp}] ${clientIP} → 404 ${req.url}`);
    }
});

// ── Start ─────────────────────────────────────────────────────
initData();

server.listen(PORT, '0.0.0.0', () => {
    const ips = getLocalIPs();

    console.log('\n╔══════════════════════════════════════════════════╗');
    console.log('║   IoT Firmware Update Server (Node.js)           ║');
    console.log('╚══════════════════════════════════════════════════╝');
    console.log(`\n  Port     : ${PORT}`);
    console.log(`  Firmware : ${firmwareSize} bytes (seq=${SEQ_NUM})`);
    console.log(`  SHA-256  : ${firmwareHash.toString('hex').substring(0, 32)}...`);
    console.log(`  Source   : ${BIN_FILE || 'auto-generated test data'}`);

    console.log('\n  Your IP addresses:');
    ips.forEach(ip => {
        console.log(`    ${ip.name}: ${ip.address}`);
    });

    console.log(`\n  Dashboard : http://localhost:${PORT}/`);
    if (ips.length > 0) {
        console.log(`  From phone: http://${ips[0].address}:${PORT}/`);
    }

    console.log('\n  ┌─────────────────────────────────────────────┐');
    console.log('  │  Normal Endpoints:                           │');
    console.log('  │    GET /fw/manifest    — Valid manifest       │');
    console.log('  │    GET /fw/image       — Valid firmware       │');
    console.log('  │                                               │');
    console.log('  │  Edge-Case Test Endpoints:                    │');
    console.log('  │    GET /fw/manifest/corrupt  — Wrong hash     │');
    console.log('  │    GET /fw/manifest/rollback — seq=0          │');
    console.log('  │    GET /fw/manifest/unsigned — Zero sig       │');
    console.log('  │    GET /fw/manifest/badmagic — Bad magic      │');
    console.log('  │    GET /fw/image/tampered    — Flipped byte   │');
    console.log('  │    GET /fw/manifest/unauth   — Auth check     │');
    console.log('  └─────────────────────────────────────────────┘');

    console.log('\n  Waiting for ESP8266 connections...\n');
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`[ERROR] Port ${PORT} is already in use. Try: node server.js --port ${PORT + 1}`);
    } else {
        console.error(`[ERROR] ${err.message}`);
    }
    process.exit(1);
});
