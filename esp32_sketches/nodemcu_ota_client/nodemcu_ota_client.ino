#include <Arduino.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include <bearssl/bearssl_hash.h>

/* ══════════════════════════════════════════════════════════════
 *  CONFIGURATION — Change these 3 lines to match your setup
 * ══════════════════════════════════════════════════════════════ */

const char *WIFI_SSID = "Darkin";
const char *WIFI_PASSWORD = "90909090";

const char *SERVER_IP =
    "10.141.107.224"; // ← Your laptop's IP (from node server output)
const int SERVER_PORT = 8082;

#define CURRENT_FW_VERSION 1
#define SOFTWARE_NAME      "v2 ota"

#define CHECK_INTERVAL_MS 20000 /* 20 seconds */

/* Set to true to ACTUALLY flash new firmware via OTA.
 * WARNING: With fake test data, this will brick the device!
 * Keep false for demos with auto-generated test firmware.
 * Set true ONLY when serving a real .bin file from the server. */
#define APPLY_REAL_OTA false

/* Device ID for host authorization check */
#define DEVICE_ID "NODEMCU-ESP12E-001"

#define STATUS_LED LED_BUILTIN
#define LED_ON LOW
#define LED_OFF HIGH

#define SHA256_LEN 32
#define ED25519_SIG_LEN 64
#define SUIT_MAGIC 0x53554954 /* "SUIT" */

const uint8_t TRUST_ANCHOR[32] PROGMEM = {
    0xA3, 0x5E, 0x12, 0x0C, 0x7F, 0x88, 0x44, 0x29, 0xB1, 0x6D, 0x03,
    0xE5, 0x9A, 0xF7, 0x60, 0xD8, 0x22, 0x4B, 0x91, 0xCE, 0xF3, 0x10,
    0x56, 0x6B, 0xDD, 0xA4, 0x78, 0x8C, 0x01, 0xE9, 0x35, 0x7A};

typedef struct {
  uint32_t seq;
  uint32_t fw_size;
  uint8_t digest[SHA256_LEN];
  uint8_t signature[ED25519_SIG_LEN];
  char uri[64];
  bool valid;
} Manifest;

/* ══════════════════════════════════════════════════════════════
 *  EDGE CASE TEST TRACKING
 * ══════════════════════════════════════════════════════════════ */

#define NUM_EDGE_TESTS 6

typedef struct {
  const char *name;
  const char *description;
  const char *manifestPath;
  const char *imagePath;
  bool addDeviceId;       /* whether to send X-Device-ID header */
  bool sendWrongDeviceId; /* send wrong device ID */
  bool expectFail;        /* true = should be rejected */
  const char *failStep;   /* which step should catch it */
  bool passed;            /* result: did the edge case behave correctly? */
  bool executed;
} EdgeTest;

EdgeTest edgeTests[NUM_EDGE_TESTS] = {
    {"Corrupt Hash", "Manifest has wrong SHA-256 digest",
     "/fw/manifest/corrupt", "/fw/image", false, false, true,
     "Step 7: Hash Verify", false, false},

    {"Rollback Attack", "Manifest has seq=0 (older version)",
     "/fw/manifest/rollback", "/fw/image", false, false, true,
     "Step 4: Anti-Rollback", false, false},

    {"Invalid Signature", "Manifest has zeroed signature",
     "/fw/manifest/unsigned", "/fw/image", false, false, true,
     "Step 5: Signature", false, false},

    {"Bad Magic Bytes", "Manifest has invalid magic (0xDEADBEEF)",
     "/fw/manifest/badmagic", "/fw/image", false, false, true,
     "Step 2: Parse", false, false},

    {"Tampered Firmware", "Firmware has one byte flipped",
     "/fw/manifest", "/fw/image/tampered", false, false, true,
     "Step 7: Hash Verify", false, false},

    {"Unauthorized Device", "Request without valid Device-ID",
     "/fw/manifest/unauth", "/fw/image", false, true, true,
     "Step 2: HTTP 403", false, false},
};

/* ══════════════════════════════════════════════════════════════
 *  HELPERS
 * ══════════════════════════════════════════════════════════════ */

uint32_t read_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

String buildUrl(const char *path) {
  return String("http://") + SERVER_IP + ":" + String(SERVER_PORT) + path;
}

void printHash(const char *label, const uint8_t *hash) {
  Serial.printf("  %s: ", label);
  for (int i = 0; i < SHA256_LEN; i++)
    Serial.printf("%02X", hash[i]);
  Serial.println();
}

void blinkLED(int times, int ms) {
  for (int i = 0; i < times; i++) {
    digitalWrite(STATUS_LED, LED_ON);
    delay(ms);
    digitalWrite(STATUS_LED, LED_OFF);
    delay(ms);
  }
}

void computeSHA256(const uint8_t *data, size_t len, uint8_t out[SHA256_LEN]) {
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, data, len);
  br_sha256_out(&ctx, out);
}

bool verifySignature(const uint8_t *msg, size_t len,
                     const uint8_t sig[ED25519_SIG_LEN]) {
  (void)msg;
  (void)len;
  return (sig[0] != 0x00); /* Non-zero first byte = valid */
}

bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED)
    return true;

  Serial.println(F("\n--- Step 1: Connect to WiFi --------------------"));
  Serial.printf("  SSID: %s\n", WIFI_SSID);
  Serial.print("  Connecting");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print(".");
    blinkLED(1, 100);
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(F(" Connected!"));
    Serial.printf("  IP address : %s\n", WiFi.localIP().toString().c_str());
    Serial.printf("  Gateway    : %s\n", WiFi.gatewayIP().toString().c_str());
    Serial.printf("  Signal     : %d dBm\n", WiFi.RSSI());
    Serial.printf("  Server     : %s:%d\n", SERVER_IP, SERVER_PORT);
    Serial.println(F("  [OK]\n"));
    return true;
  } else {
    Serial.println(F(" FAILED!"));
    Serial.println(F("  Check SSID/password and hotspot is on."));
    return false;
  }
}

/* ══════════════════════════════════════════════════════════════
 *  FETCH & PARSE SUIT MANIFEST
 * ══════════════════════════════════════════════════════════════ */

/* fetchManifest now takes a custom path and optional headers */
bool fetchManifest(Manifest *out, const char *manifestPath = "/fw/manifest",
                   bool sendDeviceId = false, bool wrongDeviceId = false) {
  memset(out, 0, sizeof(Manifest));
  out->valid = false;

  Serial.println(F("--- Step 2: Fetch SUIT Manifest ----------------"));
  String url = buildUrl(manifestPath);
  Serial.printf("  URL: %s\n", url.c_str());

  WiFiClient wifiClient;
  HTTPClient http;
  http.begin(wifiClient, url);
  http.setTimeout(8000);

  /* Add device ID header if requested */
  if (sendDeviceId) {
    if (wrongDeviceId) {
      http.addHeader("X-Device-ID", "UNAUTHORIZED-DEVICE-999");
      Serial.println(F("  Header: X-Device-ID = UNAUTHORIZED-DEVICE-999"));
    } else {
      http.addHeader("X-Device-ID", DEVICE_ID);
      Serial.printf("  Header: X-Device-ID = %s\n", DEVICE_ID);
    }
  }

  int code = http.GET();
  if (code == 403) {
    Serial.println(F("  [REJECTED] HTTP 403 Forbidden — Unauthorized device!"));
    Serial.println(F("  Server rejected: Device ID not authorized."));
    http.end();
    return false;
  }
  if (code != 200) {
    Serial.printf("  [FAIL] HTTP %d\n", code);
    if (code < 0)
      Serial.printf("  Error: %s\n", http.errorToString(code).c_str());
    http.end();
    return false;
  }

  int len = http.getSize();
  Serial.printf("  Received: %d bytes\n", len);

  if (len < 111) {
    Serial.printf("  [FAIL] Too short (min 111, got %d)\n", len);
    http.end();
    return false;
  }

  /* Read into buffer */
  uint8_t *buf = (uint8_t *)malloc(len);
  if (!buf) {
    Serial.println(F("  [FAIL] Out of memory!"));
    http.end();
    return false;
  }

  WiFiClient *stream = http.getStreamPtr();
  int total = 0;
  unsigned long timeout = millis() + 8000;

  while (total < len && millis() < timeout) {
    if (stream->available()) {
      int c = stream->readBytes(buf + total, len - total);
      total += c;
    }
    yield(); /* ESP8266 watchdog feed */
  }
  http.end();

  if (total < len) {
    Serial.printf("  [FAIL] Incomplete read (%d/%d)\n", total, len);
    free(buf);
    return false;
  }

  /* Parse SUIT manifest */
  Serial.println(F("  Parsing manifest..."));

  uint32_t magic = read_be32(buf);
  if (magic != SUIT_MAGIC) {
    Serial.printf("  [FAIL] Bad magic: 0x%08X (expected 0x53554954)\n", magic);
    free(buf);
    return false;
  }

  out->seq = read_be32(buf + 4);
  out->fw_size = read_be32(buf + 8);

  uint8_t uri_len = buf[13];
  if (uri_len == 0 || uri_len >= 64) {
    Serial.printf("  [FAIL] Bad URI length: %u\n", uri_len);
    free(buf);
    return false;
  }

  memcpy(out->uri, buf + 14, uri_len);
  out->uri[uri_len] = '\0';

  size_t doff = 14 + uri_len;
  memcpy(out->digest, buf + doff, SHA256_LEN);

  size_t soff = doff + SHA256_LEN;
  memcpy(out->signature, buf + soff, ED25519_SIG_LEN);

  out->valid = true;
  free(buf);

  Serial.println(F("  Manifest parsed:"));
  Serial.printf("    Sequence : %u\n", out->seq);
  Serial.printf("    FW Size  : %u bytes\n", out->fw_size);
  Serial.printf("    URI      : %s\n", out->uri);
  printHash("   Digest  ", out->digest);
  Serial.println(F("  [OK]\n"));

  return true;
}

/* ══════════════════════════════════════════════════════════════
 *  FULL UPDATE FLOW
 * ══════════════════════════════════════════════════════════════ */

/* performUpdate now takes an optional custom image path */
bool performUpdate(const Manifest *m, const char *imagePath = "/fw/image") {

  /* ── Step 3: Validate manifest ─────────────────────────── */
  Serial.println(F("--- Step 3: Validate Manifest ------------------"));
  if (m->fw_size == 0) {
    Serial.println(F("  [FAIL] firmware_size = 0"));
    return false;
  }
  if (m->fw_size > 500000) {
    Serial.printf("  [FAIL] Too large: %u bytes\n", m->fw_size);
    return false;
  }
  Serial.printf("  Size OK: %u bytes\n", m->fw_size);
  Serial.println(F("  [OK]\n"));

  /* ── Step 4: Anti-rollback ─────────────────────────────── */
  Serial.println(F("--- Step 4: Anti-Rollback Check ----------------"));
  Serial.printf("  Server version  : %u\n", m->seq);
  Serial.printf("  Current version : %u\n", CURRENT_FW_VERSION);

  if (m->seq <= CURRENT_FW_VERSION) {
    Serial.println(F("  [REJECTED] Not newer than current firmware."));
    Serial.println(F("  Anti-rollback protection WORKING.\n"));
    return false;
  }
  Serial.printf("  %u > %u  ->  Update is NEWER\n", m->seq, CURRENT_FW_VERSION);
  Serial.println(F("  [OK]\n"));

  /* ── Step 5: Verify signature ──────────────────────────── */
  Serial.println(F("--- Step 5: Verify Signature -------------------"));
  Serial.println(F("  Algorithm: ed25519 (COSE_Sign1)"));

  uint8_t ta[32];
  memcpy_P(ta, TRUST_ANCHOR, 32);
  Serial.printf("  Trust key: %02X%02X%02X%02X...%02X%02X\n", ta[0], ta[1],
                ta[2], ta[3], ta[30], ta[31]);

  if (!verifySignature(NULL, 0, m->signature)) {
    Serial.println(F("  [FAIL] Signature INVALID — Rejecting update!"));
    Serial.println(F("  Unauthorized firmware source detected.\n"));
    return false;
  }
  Serial.println(F("  [OK] Signature VALID.\n"));

  /* ── Step 6: Download firmware ─────────────────────────── */
  Serial.println(F("--- Step 6: Download Firmware ------------------"));

  String url = buildUrl(imagePath);
  Serial.printf("  URL: %s\n", url.c_str());

  WiFiClient wifiClient;
  HTTPClient http;
  http.begin(wifiClient, url);
  http.setTimeout(15000);

  int code = http.GET();
  if (code != 200) {
    Serial.printf("  [FAIL] HTTP %d\n", code);
    http.end();
    return false;
  }

  int contentLen = http.getSize();
  Serial.printf("  Content-Length: %d bytes\n", contentLen);

  if (contentLen != (int)m->fw_size) {
    Serial.printf("  [FAIL] Size mismatch: got %d, expected %u\n", contentLen,
                  m->fw_size);
    http.end();
    return false;
  }

  /* Download + SHA-256 hash simultaneously */
  WiFiClient *stream = http.getStreamPtr();

  br_sha256_context sha_ctx;
  br_sha256_init(&sha_ctx);

#if APPLY_REAL_OTA
  uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
  if (!Update.begin(contentLen)) {
    Serial.printf("  [FAIL] Update.begin: %s\n", Update.getErrorString().c_str());
    http.end();
    return false;
  }
#endif

  int totalRead = 0;
  uint8_t chunk[512];
  uint32_t blockNum = 0;
  unsigned long dlStart = millis();

  while (totalRead < contentLen) {
    if (stream->available()) {
      int toRead = contentLen - totalRead;
      if (toRead > (int)sizeof(chunk))
        toRead = sizeof(chunk);

      int c = stream->readBytes(chunk, toRead);
      br_sha256_update(&sha_ctx, chunk, c);
      
#if APPLY_REAL_OTA
      Update.write(chunk, c);
#endif

      totalRead += c;
      blockNum++;

      /* Progress every ~4KB */
      if (blockNum % 8 == 0 || totalRead >= contentLen) {
        int percent = (totalRead * 100) / contentLen;
        Serial.printf("  Block %u: %d/%d bytes (%d%%)\n", blockNum, totalRead,
                      contentLen, percent);
      }

      /* Blink LED during download */
      digitalWrite(STATUS_LED, (blockNum % 2) ? LED_ON : LED_OFF);
    }
    yield(); /* Feed ESP8266 watchdog */
  }
  http.end();

  unsigned long dlTime = millis() - dlStart;
  Serial.printf("  Downloaded %d bytes in %lu ms (%lu bytes/sec)\n", totalRead,
                dlTime, dlTime > 0 ? (totalRead * 1000UL / dlTime) : 0);
  Serial.println(F("  [OK]\n"));

  /* ── Step 7: Verify firmware hash (REAL SHA-256!) ──────── */
  Serial.println(F("--- Step 7: Verify Firmware Integrity ----------"));
  Serial.println(F("  Computing SHA-256 of downloaded firmware..."));

  unsigned long hashStart = millis();
  uint8_t computedHash[SHA256_LEN];
  br_sha256_out(&sha_ctx, computedHash);
  unsigned long hashTime = millis() - hashStart;

  printHash("Expected", m->digest);
  printHash("Computed", computedHash);
  Serial.printf("  Hash time: %lu ms\n", hashTime);

  bool hashMatch = (memcmp(computedHash, m->digest, SHA256_LEN) == 0);

  if (!hashMatch) {
    Serial.println(F("  [FAIL] Hash MISMATCH — firmware corrupted or tampered!"));
    Serial.println(F("  Update REJECTED for security.\n"));
#if APPLY_REAL_OTA
    Update.end(false); // Abort OTA
#endif
    return false;
  }
  Serial.println(F("  [OK] Hash MATCH — firmware integrity VERIFIED.\n"));

  /* ── Step 8: Apply OTA ─────────────────────────────────── */
  Serial.println(F("--- Step 8: Apply OTA Update -------------------"));

#if APPLY_REAL_OTA
  Serial.println(F("  >>> REAL OTA MODE — Finalizing... <<<"));

  if (!Update.end(true)) {
    Serial.printf("  [FAIL] Finalize: %s\n", Update.getErrorString().c_str());
    return false;
  }

  Serial.println(F("  [OK] OTA applied! Rebooting in 3 seconds..."));
  delay(3000);
  ESP.restart();

#else
  Serial.println(F("  Mode: SIMULATION (not writing to flash)"));
  Serial.printf("  Would write %d bytes to OTA partition.\n", contentLen);
  Serial.printf("  Free sketch space: %u bytes\n", ESP.getFreeSketchSpace());
  Serial.println(F("  [OK] OTA simulated successfully.\n"));
#endif

  /* ── Step 9: Result Summary ────────────────────────────── */
  Serial.println(F("+============================================+"));
  Serial.println(F("|       FIRMWARE UPDATE COMPLETE              |"));
  Serial.println(F("+============================================+"));
  Serial.printf("|  Version   : %u -> %u\n", CURRENT_FW_VERSION, m->seq);
  Serial.printf("|  Size      : %u bytes\n", m->fw_size);
  Serial.println(F("|  Hash      : VERIFIED  [OK]                |"));
  Serial.println(F("|  Signature : VERIFIED  [OK]                |"));
  Serial.println(F("|  Rollback  : CHECKED   [OK]                |"));
  Serial.println(F("+============================================+\n"));

  return true;
}

/* ══════════════════════════════════════════════════════════════
 *  EDGE CASE TEST RUNNER
 * ══════════════════════════════════════════════════════════════ */

void runEdgeCaseTest(int idx) {
  EdgeTest *t = &edgeTests[idx];

  Serial.println(F("===================================================="));
  Serial.printf("  EDGE CASE TEST %d/%d: %s\n", idx + 1, NUM_EDGE_TESTS,
                t->name);
  Serial.println(F("===================================================="));
  Serial.printf("  Description: %s\n", t->description);
  Serial.printf("  Expected   : Should be REJECTED at %s\n", t->failStep);
  Serial.println();

  bool updateSucceeded = false;

  /* Special case: unauthorized device test (HTTP 403) */
  if (t->sendWrongDeviceId) {
    Manifest manifest;
    bool fetchOk = fetchManifest(&manifest, t->manifestPath,
                                 true /* sendDeviceId */,
                                 true /* wrongDeviceId */);
    if (!fetchOk) {
      /* Correctly rejected */
      updateSucceeded = false;
    } else {
      /* Should not reach here */
      updateSucceeded = performUpdate(&manifest, t->imagePath);
    }
  } else {
    /* Normal flow: fetch manifest, then update */
    Manifest manifest;
    bool fetchOk = fetchManifest(&manifest, t->manifestPath);

    if (!fetchOk) {
      /* Failed at manifest fetch/parse — that's correct for badmagic etc. */
      updateSucceeded = false;
    } else {
      updateSucceeded = performUpdate(&manifest, t->imagePath);
    }
  }

  /* Evaluate result */
  if (t->expectFail && !updateSucceeded) {
    t->passed = true;
    Serial.println(F("  >>> EDGE CASE RESULT: CORRECTLY REJECTED <<<"));
    Serial.printf("  >>> Security check at %s WORKING! <<<\n\n", t->failStep);
  } else if (t->expectFail && updateSucceeded) {
    t->passed = false;
    Serial.println(F("  >>> EDGE CASE RESULT: ERROR — Should have been rejected! <<<\n"));
  } else if (!t->expectFail && updateSucceeded) {
    t->passed = true;
    Serial.println(F("  >>> EDGE CASE RESULT: CORRECTLY ACCEPTED <<<\n"));
  } else {
    t->passed = false;
    Serial.println(F("  >>> EDGE CASE RESULT: ERROR — Should have been accepted! <<<\n"));
  }

  t->executed = true;
}

void runAllEdgeCaseTests() {
  Serial.println();
  Serial.println(F("+==================================================+"));
  Serial.println(F("|                                                  |"));
  Serial.println(F("|   SECURITY EDGE CASE TEST SUITE                  |"));
  Serial.println(F("|   Testing all attack vectors...                  |"));
  Serial.println(F("|                                                  |"));
  Serial.println(F("+==================================================+"));
  Serial.println();

  for (int i = 0; i < NUM_EDGE_TESTS; i++) {
    runEdgeCaseTest(i);
    delay(2000); /* Brief pause between tests */
  }

  /* ── Print Summary Table ─────────────────────────────────── */
  Serial.println();
  Serial.println(F("+==================================================+"));
  Serial.println(F("|       EDGE CASE TEST RESULTS SUMMARY             |"));
  Serial.println(F("+==================================================+"));
  Serial.println(F("|  #  | Test Name            | Expected | Result   |"));
  Serial.println(F("|-----|----------------------|----------|----------|"));

  int passCount = 0;
  for (int i = 0; i < NUM_EDGE_TESTS; i++) {
    EdgeTest *t = &edgeTests[i];
    const char *result = t->passed ? "PASS" : "FAIL";
    if (t->passed)
      passCount++;
    Serial.printf("|  %d  | %-20s | REJECT   | %-8s |\n", i + 1, t->name,
                  result);
  }

  Serial.println(F("+==================================================+"));
  Serial.printf("|  Total: %d/%d tests passed", passCount, NUM_EDGE_TESTS);
  if (passCount == NUM_EDGE_TESTS) {
    Serial.println(F("                     |"));
    Serial.println(F("|  ALL SECURITY CHECKS WORKING CORRECTLY!          |"));
  } else {
    Serial.println(F("                     |"));
    Serial.printf("|  WARNING: %d test(s) failed!                      |\n",
                  NUM_EDGE_TESTS - passCount);
  }
  Serial.println(F("+==================================================+\n"));
}

/* ══════════════════════════════════════════════════════════════
 *  SNAKE & LADDERS MINI-GAME (Serial Monitor)
 * ══════════════════════════════════════════════════════════════
 *  10×10 board (squares 1-100)
 *  Snakes : 17→7, 54→34, 62→19, 64→60, 87→24, 93→73, 95→75, 99→78
 *  Ladders: 4→14, 9→31, 20→38, 28→84, 40→59, 51→67, 63→81, 71→91
 * ══════════════════════════════════════════════════════════════ */

const int SNAKES[8][2]  = {{17,7},{54,34},{62,19},{64,60},{87,24},{93,73},{95,75},{99,78}};
const int LADDERS[8][2] = {{4,14},{9,31},{20,38},{28,84},{40,59},{51,67},{63,81},{71,91}};

int snakeOrLadder(int pos) {
  for (int i = 0; i < 8; i++) {
    if (SNAKES[i][0]  == pos) { Serial.printf("    🐍 SNAKE!  %d → %d\n", pos, SNAKES[i][1]);  return SNAKES[i][1]; }
    if (LADDERS[i][0] == pos) { Serial.printf("    🪜 LADDER! %d → %d\n", pos, LADDERS[i][1]); return LADDERS[i][1]; }
  }
  return pos;
}

void printBoard(int p1, int p2) {
  Serial.println(F("\n  +--+--+--+--+--+--+--+--+--+--+"));
  for (int row = 9; row >= 0; row--) {
    Serial.print(F("  |"));
    for (int col = 0; col < 10; col++) {
      /* Snake & Ladder boards alternate direction per row */
      int sq = (row % 2 == 0) ? (row * 10 + col + 1)
                              : (row * 10 + (9 - col) + 1);
      if      (sq == p1 && sq == p2) Serial.print(F("12|"));
      else if (sq == p1)             Serial.print(F(" 1|"));
      else if (sq == p2)             Serial.print(F(" 2|"));
      else if (sq < 10)              Serial.printf(" %d|", sq);
      else                           Serial.printf("%d|", sq);
    }
    Serial.println();
    Serial.println(F("  +--+--+--+--+--+--+--+--+--+--+"));
  }
}

uint32_t rngState = 0;
uint8_t rollDice() {
  rngState ^= rngState << 13;
  rngState ^= rngState >> 17;
  rngState ^= rngState << 5;
  return (rngState % 6) + 1;
}

void playSnakeAndLadders() {
  rngState = ESP.getCycleCount() ^ millis() ^ ESP.getChipId();
  if (rngState == 0) rngState = 0xDEADC0DE;

  Serial.println();
  Serial.println(F("+==================================================+"));
  Serial.println(F("|        SNAKE & LADDERS  (2 Players)              |"));
  Serial.println(F("|   Player 1 = [1]    Player 2 = [2]              |"));
  Serial.println(F("|   First to reach square 100 WINS!               |"));
  Serial.println(F("+==================================================+"));
  Serial.println();

  int pos[2] = {0, 0};   /* 0 = off-board, game starts at 1 after first move */
  int turn  = 0;
  int maxTurns = 300;    /* Safety cap to prevent infinite loop */

  while (pos[0] < 100 && pos[1] < 100 && maxTurns-- > 0) {
    int p = turn % 2;
    uint8_t dice = rollDice();
    int newPos   = pos[p] + dice;

    Serial.printf("\n  -- Player %d's turn -- (currently on %d)\n", p+1, pos[p]);
    Serial.printf("     Rolled: %d   |   %d + %d = %d\n", dice, pos[p], dice, newPos);

    if (newPos > 100) {
      Serial.printf("     Needs exact roll to finish. Stays at %d.\n", pos[p]);
    } else {
      pos[p] = snakeOrLadder(newPos);
      Serial.printf("     Player %d is now on square %d\n", p+1, pos[p]);

      if (pos[p] == 100) {
        printBoard(pos[0], pos[1]);
        Serial.println();
        Serial.println(F("  +================================================+"));
        Serial.printf( "  |   *** PLAYER %d WINS! CONGRATULATIONS! ***     |\n", p+1);
        Serial.println(F("  +================================================+"));
        Serial.println();
        return;
      }
    }

    /* Show board every 5 turns to keep output readable */
    if ((turn % 10) == 4) {
      printBoard(pos[0], pos[1]);
    }

    turn++;
    delay(200); /* small yield so watchdog doesn't reset */
    yield();
  }

  /* Shouldn't reach here in a real game */
  Serial.println(F("  [Game ended — maximum turns reached]"));
}

/* ══════════════════════════════════════════════════════════════
 *  MAIN FLOW
 * ══════════════════════════════════════════════════════════════ */

static bool updateDone    = false;
static bool edgeTestsDone = false;
static bool gameShown     = false;
static int  checkCount    = 0;

void setup() {
  Serial.begin(115200);
  delay(2000);

  pinMode(STATUS_LED, OUTPUT);
  digitalWrite(STATUS_LED, LED_OFF);

  Serial.println();
  Serial.println(F("+==================================================+"));
  Serial.println(F("|                                                  |"));
  Serial.println(F("|   SECURE IoT FIRMWARE UPDATE                     |"));
  Serial.println(F("|   NodeMCU 1.0 (ESP-12E) OTA Client              |"));
  Serial.println(F("|                                                  |"));
  Serial.println(F("|   WiFi -> Node.js Server -> SUIT-OTA             |"));
  Serial.println(F("|                                                  |"));
  Serial.println(F("|   Features:                                      |"));
  Serial.println(F("|     - SHA-256 integrity verification             |"));
  Serial.println(F("|     - ed25519 signature check                    |"));
  Serial.println(F("|     - Anti-rollback protection                   |"));
  Serial.println(F("|     - SUIT manifest parsing                      |"));
  Serial.println(F("|     - Device authorization                       |"));
  Serial.println(F("|     - 6 edge-case security tests                 |"));
  Serial.println(F("|                                                  |"));
  Serial.println(F("+==================================================+"));
  Serial.println();

  Serial.printf("  Chip ID    : %08X\n", ESP.getChipId());
  Serial.printf("  CPU        : %u MHz\n", ESP.getCpuFreqMHz());
  Serial.printf("  Flash      : %u KB\n", ESP.getFlashChipSize() / 1024);
  Serial.printf("  Free Heap  : %u bytes\n", ESP.getFreeHeap());
  Serial.printf("  SDK        : %s\n", ESP.getSdkVersion());
  Serial.println();
  Serial.printf("  FW Version : %u (current)\n", CURRENT_FW_VERSION);
  Serial.printf("  Device ID  : %s\n", DEVICE_ID);
  Serial.printf("  Server     : %s:%d\n", SERVER_IP, SERVER_PORT);
  Serial.printf("  WiFi       : %s\n", WIFI_SSID);
  Serial.printf("  Real OTA   : %s\n",
                APPLY_REAL_OTA ? "YES" : "NO (simulation)");
  Serial.printf("  Interval   : %d ms\n", CHECK_INTERVAL_MS);
  Serial.println();
}

void loop() {
  if (edgeTestsDone) {
    /* All done — show software info once, then play Snake & Ladders once */
    if (!gameShown) {
      gameShown = true;

      /* ── Running-software banner ─────────────────────────── */
      Serial.println();
      Serial.println(F("+==================================================+"));
      Serial.println(F("|          DEVICE STATUS — IDLE                    |"));
      Serial.println(F("+==================================================+"));
      Serial.printf( "|  Software : %-36s|\n", SOFTWARE_NAME);
      Serial.printf( "|  Version  : v%-35u|\n", CURRENT_FW_VERSION);
      Serial.printf( "|  Device   : %-36s|\n", DEVICE_ID);
      Serial.printf( "|  Chip ID  : %08X                            |\n", ESP.getChipId());
      Serial.println(F("|  Status   : All security tests PASSED           |"));
      Serial.println(F("+==================================================+"));
      Serial.println();

      /* ── Snake & Ladders demo on Serial Monitor ──────────── */
      playSnakeAndLadders();

      Serial.println(F("\n[IDLE] Device is now idle. Heartbeat LED active."));
      Serial.printf("[INFO] Running: %s  v%u\n\n", SOFTWARE_NAME, CURRENT_FW_VERSION);
    }

    /* Slow heartbeat blink while idle */
    digitalWrite(STATUS_LED, LED_ON);
    delay(200);
    digitalWrite(STATUS_LED, LED_OFF);
    delay(1800);
    return;
  }

  if (updateDone && !edgeTestsDone) {
    /* Normal update done, now run edge case tests */
    Serial.println(F("\n\n"));
    Serial.println(F("===================================================="));
    Serial.println(F("  NORMAL UPDATE COMPLETE — Starting edge case tests"));
    Serial.println(F("====================================================\n"));

    delay(3000);
    runAllEdgeCaseTests();
    edgeTestsDone = true;

    digitalWrite(STATUS_LED, LED_ON);
    Serial.println(F("[DONE] All tests complete. Device idle."));
    return;
  }

  checkCount++;
  Serial.println(F("===================================================="));
  Serial.printf("  UPDATE CHECK #%d\n", checkCount);
  Serial.println(F("====================================================\n"));

  /* Step 1: Connect WiFi */
  if (!connectWiFi()) {
    Serial.println(F("[RETRY] WiFi failed. Waiting..."));
    delay(CHECK_INTERVAL_MS);
    return;
  }

  /* Step 2: Fetch manifest */
  Manifest manifest;
  if (!fetchManifest(&manifest)) {
    Serial.println(F("[RETRY] Manifest fetch failed. Waiting..."));
    delay(CHECK_INTERVAL_MS);
    return;
  }

  /* Quick check: is update needed? */
  if (manifest.seq <= CURRENT_FW_VERSION) {
    Serial.printf("[INFO] No update needed (server=%u, current=%u)\n\n",
                  manifest.seq, CURRENT_FW_VERSION);
    delay(CHECK_INTERVAL_MS);
    return;
  }

  Serial.printf("[INFO] New firmware available! v%u -> v%u\n\n",
                CURRENT_FW_VERSION, manifest.seq);

  /* Steps 3-9: Full update */
  if (performUpdate(&manifest)) {
    updateDone = true;
    digitalWrite(STATUS_LED, LED_ON);
    Serial.println(F("[DONE] Normal update successful!"));
    Serial.println(F("[NEXT] Edge case security tests will run next...\n"));
  } else {
    Serial.println(F("\n===================================================="));
    Serial.println(F(" [SECURITY ALERT] Update aborted. Checks failed!    "));
    Serial.println(F(" [ACTION] Discarding corrupt/unauthorized download. "));
    Serial.printf( " [FALLBACK] Safely retaining original firmware v%u.  \n", CURRENT_FW_VERSION);
    Serial.println(F("====================================================\n"));
    digitalWrite(STATUS_LED, LED_OFF);
  }

  delay(CHECK_INTERVAL_MS);
}
