/*
 * SafeDrop — automatic parcel lock box (ESP32 DevKit, WROOM-32)
 *
 * ESP32 variant of firmware/SafeDrop/SafeDrop.ino — identical behavior and
 * device API, different board support. Wiring:
 * docs/SafeDrop_Wiring_Guide_3_ESP32.md
 *
 * Flow: the box polls /api/device/sync every ~3 s while idle. The driver
 * types the 6-digit one-time passcode on the keypad and presses '#'. On a
 * match the box wipes the code from RAM, records the used codeId in flash
 * (so a reboot can't bring it back), unlocks the servo and reports 'used'.
 * The driver leaves the parcel, takes the payment the owner left inside,
 * closes the lid and presses '#' again — the box locks and reports
 * 'closed'. Three wrong entries trigger a 30 s lockout.
 *
 * Two provisioning paths:
 *
 * 1. PROTOTYPE (hard-coded): paste your Wi-Fi credentials, SERVER_HOST,
 *    BOX_ID and DEVICE_KEY into secrets.h and flash. Leave BOX_ID as "" to
 *    use the dynamic path instead.
 *
 * 2. PRODUCTION (dynamic, no reflash): pair a box in the app to get a
 *    claim code. Hold '*' on the keypad for 5 s at power-on — the box
 *    starts setup mode, opens the "SafeDrop-Setup" Wi-Fi hotspot, and you
 *    enter your Wi-Fi + claim code at http://192.168.4.1 from your phone.
 *    The box claims its device key from POST /api/device/claim, stores
 *    everything in flash and reboots into normal mode.
 *
 * Outbound HTTPS only (no inbound connections, no port forwarding).
 * NOTE: the ESP32 has no certificate store on the Wi-Fi module (the UNO R4
 * variant loads its CA with the Arduino Firmware Updater), so the root CA
 * for SERVER_HOST is embedded from server_root_ca.h (ISRG Root X1 — what
 * Vercel serves by default). Swap it if your host uses another CA. For a
 * quick bench test you may uncomment ALLOW_INSECURE_TLS below, which
 * disables the certificate check entirely — never ship a box like that.
 *
 * Board: "ESP32 Dev Module" (Tools → Board → esp32).
 * Libraries: WiFi, WiFiClientSecure (built in), ArduinoHttpClient,
 * ArduinoJson (v7), Keypad, LiquidCrystal_I2C, ESP32Servo, EEPROM
 * (built in — NVS-backed emulation).
 */

// Uncomment ONLY for bench testing without a matching CA certificate:
//#define ALLOW_INSECURE_TLS

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <ArduinoHttpClient.h>
#include <ArduinoJson.h>
#include <Keypad.h>
#include <LiquidCrystal_I2C.h>
#include <Wire.h>
#include <ESP32Servo.h>
#include <EEPROM.h>

#include "server_root_ca.h"
#include "secrets.h"

// ---------- pins (30-pin ESP32 DevKit; see the wiring guide) ----------
const byte ROWS = 4, COLS = 4;
char keys[ROWS][COLS] = {
  {'1', '2', '3', 'A'},
  {'4', '5', '6', 'B'},
  {'7', '8', '9', 'C'},
  {'*', '0', '#', 'D'}
};
byte rowPins[ROWS] = {32, 33, 25, 26};
byte colPins[COLS] = {27, 14, 13, 16};
Keypad keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

const byte PIN_GREEN = 18;
const byte PIN_RED = 19;
const byte PIN_SERVO = 23;
const byte PIN_BUZZER = 17;
const byte PIN_SDA = 21;
const byte PIN_SCL = 22;

const int SERVO_LOCKED_ANGLE = 0;
const int SERVO_UNLOCKED_ANGLE = 90;

// setup-mode hotspot
const char* AP_SSID = "SafeDrop-Setup";
const char* AP_PASS = "safedrop123";

const unsigned long POLL_INTERVAL_MS = 3000;
const unsigned long KEYPAD_QUIET_MS = 5000;
const unsigned long LOCKOUT_MS = 30000UL;
const unsigned long RED_FLASH_MS = 2000;
const byte MAX_WRONG_BEFORE_LOCKOUT = 3;
const byte CODE_LEN = 6;
const unsigned long OPEN_GUARD_MS = 1500;  // '#' ignored this long after unlocking

// ---------- flash: used codeIds (survive reboot) ----------
const byte EE_MAGIC = 0x5D;
const int EE_MAGIC_ADDR = 0;
const int EE_COUNT_ADDR = 1;
const int EE_SLOTS_ADDR = 2;
const int CODE_ID_LEN = 16;           // 16 hex chars from the server
const int SLOT_SIZE = CODE_ID_LEN + 1;
const int MAX_SLOTS = 8;
// codeId store ends at 2 + 8*17 = 138

// ---------- flash: provisioning config ----------
const byte CFG_MAGIC_VAL = 0xA5;
const int CFG_MAGIC_ADDR = 400;
const int CFG_SSID_ADDR = 401;        // 33 bytes
const int CFG_PASS_ADDR = 434;        // 65 bytes
const int CFG_BOXID_ADDR = 499;       // 24 bytes
const int CFG_KEY_ADDR = 523;         // 65 bytes
const int CFG_NEED_CLAIM_ADDR = 588;  // 1 byte
const int CFG_CLAIM_ADDR = 589;       // 13 bytes

char wifiSsid[33] = "";
char wifiPass[65] = "";
char boxId[24] = "";
char deviceKey[65] = "";
char claimCode[13] = "";
// volatile: written/read across the network task and the main loop task
bool volatile needsClaim = false;
unsigned long lastClaimAttemptMs = 0;

// ---------- state machine (IDLE / KEYPAD / OPEN / LOCKOUT) ----------
enum State { STATE_IDLE, STATE_KEYPAD, STATE_OPEN, STATE_LOCKOUT };
State volatile state = STATE_IDLE;

char activeCode[CODE_LEN + 1] = "";  // the passcode to match
char activeCodeId[CODE_ID_LEN + 1] = "";
unsigned long codeExpiresMs = 0;
unsigned long lastPollMs = 0;
unsigned long volatile lastKeyMs = 0;
unsigned long lockoutUntilMs = 0;
unsigned long redOffAtMs = 0;
unsigned long openedAtMs = 0;  // when the box unlocked ('#' guard window)
byte wrongCount = 0;
char entry[CODE_LEN + 1] = "";
byte entryLen = 0;

// pending event queue, flushed when Wi-Fi is up
bool volatile pendingUsed = false;
bool volatile pendingWrong = false;
bool volatile pendingClosed = false;
char pendingUsedCodeId[CODE_ID_LEN + 1] = "";

WiFiClientSecure wifiClient;
HttpClient http(wifiClient, SERVER_HOST, 443);
LiquidCrystal_I2C lcd(0x27, 16, 2);
Servo lockServo;
WiFiServer setupServer(80);

const char* maskedEntry();

// Keypad inputs arrive through this queue from the fast scan task, so no
// press is lost while HTTPS requests, delays or Wi-Fi reconnects block the
// main loop. Created in setup(); the main loop drains and processes it.
QueueHandle_t keyQueue;

void keypadScanTask(void*) {
  for (;;) {
    char key = keypad.getKey();
    if (key) xQueueSend(keyQueue, &key, 0);
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

// All blocking network work (polls, event reports, claim, Wi-Fi reconnect)
// runs in its own task; the main loop only handles UI/state, so keypad
// presses and LCD updates never wait on HTTPS.
QueueHandle_t netEventQueue;
SemaphoreHandle_t stateMutex;

// network task -> main loop UI events
enum { NET_EVENT_CODE_CLEARED = 1, NET_EVENT_CLAIM_OK, NET_EVENT_CLAIM_FAILED };

void netPushEvent(int type) {
  xQueueSend(netEventQueue, &type, 0);
}

/** Store the fetched one-time code (called from the network task). */
void setActiveCode(const char* codeId, const char* code, unsigned long expiresAtMs) {
  if (xSemaphoreTake(stateMutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
  strncpy(activeCodeId, codeId, CODE_ID_LEN);
  activeCodeId[CODE_ID_LEN] = '\0';
  strncpy(activeCode, code, CODE_LEN);
  activeCode[CODE_LEN] = '\0';
  codeExpiresMs = expiresAtMs;
  xSemaphoreGive(stateMutex);
}

// ---------- small helpers ----------
// The ESP32 EEPROM library emulates EEPROM over NVS flash: it buffers
// writes in RAM and only persists them on EEPROM.commit(), so every write
// batch must be flushed explicitly.
bool eeDirty = false;

void eeUpdate(int addr, byte val) {
  if (EEPROM.read(addr) != val) {
    EEPROM.write(addr, val);
    eeDirty = true;
  }
}

void eeCommit() {
  if (eeDirty) {
    EEPROM.commit();
    eeDirty = false;
  }
}

void lcdShow(const char* line1, const char* line2) {
  char l1[17], l2[17];
  snprintf(l1, sizeof(l1), "%-16s", line1);
  snprintf(l2, sizeof(l2), "%-16s", line2);
  lcd.setCursor(0, 0);
  lcd.print(l1);
  lcd.setCursor(0, 1);
  lcd.print(l2);
}

// tone() is LEDC-backed in the ESP32 Arduino core. If your core version
// lacks it, replace this helper with a small LEDC setup + ledcWriteTone.
void beep(int freq, int durMs) {
  tone(PIN_BUZZER, freq, durMs);
}

void lockBolt() {
  lockServo.write(SERVO_LOCKED_ANGLE);
}

void unlockBolt() {
  lockServo.write(SERVO_UNLOCKED_ANGLE);
}

void flashRed() {
  digitalWrite(PIN_RED, HIGH);
  redOffAtMs = millis() + RED_FLASH_MS;
}

void writeEeStr(int addr, const char* s, int maxLen) {
  int len = strlen(s);
  if (len > maxLen - 1) len = maxLen - 1;
  for (int i = 0; i < maxLen; i++) {
    byte v = i < len ? (byte)s[i] : 0;
    eeUpdate(addr + i, v);
  }
}

void readEeStr(int addr, char* out, int maxLen) {
  for (int i = 0; i < maxLen - 1; i++) out[i] = (char)EEPROM.read(addr + i);
  out[maxLen - 1] = '\0';
}

// ---------- provisioning config ----------
void loadConfig() {
  wifiSsid[0] = wifiPass[0] = boxId[0] = deviceKey[0] = claimCode[0] = '\0';
  needsClaim = false;

  if (EEPROM.read(CFG_MAGIC_ADDR) == CFG_MAGIC_VAL) {
    readEeStr(CFG_SSID_ADDR, wifiSsid, sizeof(wifiSsid));
    readEeStr(CFG_PASS_ADDR, wifiPass, sizeof(wifiPass));
    readEeStr(CFG_BOXID_ADDR, boxId, sizeof(boxId));
    readEeStr(CFG_KEY_ADDR, deviceKey, sizeof(deviceKey));
    readEeStr(CFG_CLAIM_ADDR, claimCode, sizeof(claimCode));
    needsClaim = EEPROM.read(CFG_NEED_CLAIM_ADDR) == 1;
  }

  // secrets.h fallbacks (hard-coded prototype path)
  if (wifiSsid[0] == '\0' && strlen(WIFI_SSID) > 0) {
    strncpy(wifiSsid, WIFI_SSID, sizeof(wifiSsid) - 1);
  }
  if (wifiPass[0] == '\0' && strlen(WIFI_PASS) > 0) {
    strncpy(wifiPass, WIFI_PASS, sizeof(wifiPass) - 1);
  }
  if (!needsClaim && boxId[0] == '\0' && strlen(BOX_ID) > 0) {
    strncpy(boxId, BOX_ID, sizeof(boxId) - 1);
  }
  if (!needsClaim && deviceKey[0] == '\0' && strlen(DEVICE_KEY) > 0) {
    strncpy(deviceKey, DEVICE_KEY, sizeof(deviceKey) - 1);
  }
}

void writeClaimConfig(const char* ssid, const char* pass, const char* code) {
  eeUpdate(CFG_MAGIC_ADDR, CFG_MAGIC_VAL);
  writeEeStr(CFG_SSID_ADDR, ssid, (int)sizeof(wifiSsid));
  writeEeStr(CFG_PASS_ADDR, pass, (int)sizeof(wifiPass));
  writeEeStr(CFG_BOXID_ADDR, "", (int)sizeof(boxId));
  writeEeStr(CFG_KEY_ADDR, "", (int)sizeof(deviceKey));
  writeEeStr(CFG_CLAIM_ADDR, code, (int)sizeof(claimCode));
  eeUpdate(CFG_NEED_CLAIM_ADDR, 1);
  eeCommit();
}

// ---------- flash used-codeId store ----------
void eepromInit() {
  if (EEPROM.read(EE_MAGIC_ADDR) != EE_MAGIC) {
    eeUpdate(EE_MAGIC_ADDR, EE_MAGIC);
    eeUpdate(EE_COUNT_ADDR, 0);
    eeCommit();
  }
}

byte eepromCount() {
  byte n = EEPROM.read(EE_COUNT_ADDR);
  return n > MAX_SLOTS ? MAX_SLOTS : n;
}

bool eepromHasCodeId(const char* codeId) {
  byte n = eepromCount();
  for (byte i = 0; i < n; i++) {
    bool match = true;
    for (int j = 0; j < CODE_ID_LEN; j++) {
      if (EEPROM.read(EE_SLOTS_ADDR + i * SLOT_SIZE + j) != codeId[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

void eepromAddCodeId(const char* codeId) {
  byte n = eepromCount();
  if (n == MAX_SLOTS) {
    // shift out the oldest, keep the newest MAX_SLOTS
    for (byte i = 1; i < MAX_SLOTS; i++) {
      for (int j = 0; j < SLOT_SIZE; j++) {
        byte v = EEPROM.read(EE_SLOTS_ADDR + i * SLOT_SIZE + j);
        eeUpdate(EE_SLOTS_ADDR + (i - 1) * SLOT_SIZE + j, v);
      }
    }
    n = MAX_SLOTS - 1;
  }
  for (int j = 0; j < CODE_ID_LEN; j++) {
    eeUpdate(EE_SLOTS_ADDR + n * SLOT_SIZE + j, (byte)codeId[j]);
  }
  eeUpdate(EE_SLOTS_ADDR + n * SLOT_SIZE + CODE_ID_LEN, '\0');
  eeUpdate(EE_COUNT_ADDR, n + 1);
  eeCommit();
}

// ---------- Wi-Fi ----------
void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;
  Serial.print("Connecting to Wi-Fi");
  WiFi.begin(wifiSsid, wifiPass);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(300);
    Serial.print(".");
  }
  Serial.println(WiFi.status() == WL_CONNECTED ? " ok" : " FAILED");
}

// ---------- HTTP ----------
void clearCode() {
  if (xSemaphoreTake(stateMutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
  activeCode[0] = '\0';
  activeCodeId[0] = '\0';
  codeExpiresMs = 0;
  xSemaphoreGive(stateMutex);
}

/**
 * POST JSON. Adds the x-device-key header unless withAuth is false
 * (the /claim call happens before the box has a key).
 * Returns true on HTTP 200 and puts the response body in `response`.
 */
bool postJson(const char* path, const char* payload, bool withAuth,
              String& response) {
  http.beginRequest();
  int err = http.post(path);
  if (err != 0) {
    http.stop();
    return false;
  }
  if (withAuth) http.sendHeader("x-device-key", deviceKey);
  http.sendHeader("Content-Type", "application/json");
  http.sendHeader("Content-Length", (int)strlen(payload));
  http.beginBody();
  http.print(payload);
  http.endRequest();

  int status = http.responseStatusCode();
  response = http.responseBody();
  // Keep-alive: close only on failure so the next request reuses the TLS
  // session; a stalled server-side session reconnects on the next call.
  if (status <= 0) http.stop();
  return status == 200;
}

/** Fire-and-forget event POSTs; safe to fail (queued and retried). */
bool postEvent(const char* path, const char* payload) {
  String unused;
  return postJson(path, payload, true, unused);
}

/** GET /sync with the auth header; returns the body or "" on failure. */
String getSync(const char* path) {
  http.beginRequest();
  int err = http.get(path);
  if (err != 0) {
    http.stop();
    return "";
  }
  http.sendHeader("x-device-key", deviceKey);
  http.endRequest();

  int status = http.responseStatusCode();
  String body = http.responseBody();
  // Keep-alive: see postJson — close only when the session is broken.
  if (status <= 0) http.stop();
  return status == 200 ? body : "";
}

/** Flush queued reports; safe to fail (retried on the next loop pass). */
void flushPendingEvents() {
  if (WiFi.status() != WL_CONNECTED) return;

  if (pendingUsed) {
    char payload[96];
    snprintf(payload, sizeof(payload),
             "{\"boxId\":\"%s\",\"codeId\":\"%s\"}", boxId,
             pendingUsedCodeId);
    if (postEvent("/api/device/used", payload)) {
      pendingUsed = false;
      pendingUsedCodeId[0] = '\0';
      Serial.println("Reported: used");
    }
  }
  if (pendingWrong) {
    char payload[64];
    snprintf(payload, sizeof(payload),
             "{\"boxId\":\"%s\",\"result\":\"wrong\"}", boxId);
    if (postEvent("/api/device/attempt", payload)) {
      pendingWrong = false;
      Serial.println("Reported: wrong");
    }
  }
  if (pendingClosed) {
    char payload[32];
    snprintf(payload, sizeof(payload), "{\"boxId\":\"%s\"}", boxId);
    if (postEvent("/api/device/closed", payload)) {
      pendingClosed = false;
      Serial.println("Reported: closed");
    }
  }
}

/**
 * Ask the server for the active code. On success, stores it in RAM with a
 * local expiry (the box has no reliable clock). codeIds already in flash
 * are ignored — a reboot can't resurrect a used code.
 */
void pollSync() {
  char path[96];
  snprintf(path, sizeof(path), "/api/device/sync?boxId=%s", boxId);

  String body = getSync(path);
  if (body.length() == 0) return;

  JsonDocument doc;
  DeserializationError jsonErr = deserializeJson(doc, body);
  if (jsonErr) return;

  if (doc["none"].is<bool>()) {
    bool hadCode;
    if (xSemaphoreTake(stateMutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
    hadCode = activeCode[0] != '\0';
    xSemaphoreGive(stateMutex);
    if (hadCode) {
      clearCode();
      netPushEvent(NET_EVENT_CODE_CLEARED);
    }
    return;
  }

  const char* codeId = doc["codeId"];
  const char* code = doc["code"];
  long ttlSeconds = doc["ttlSeconds"] | 0;
  if (codeId == nullptr || code == nullptr || ttlSeconds <= 0) return;

  if (eepromHasCodeId(codeId)) {
    Serial.println("Ignoring already-used codeId");
    return;
  }

  setActiveCode(codeId, code, millis() + (unsigned long)ttlSeconds * 1000UL);
  Serial.print("Code received, ttl(s)=");
  Serial.println(ttlSeconds);
}

// ---------- claim (dynamic pairing) ----------
bool tryClaim() {
  if (strlen(claimCode) == 0) return false;

  char payload[48];
  snprintf(payload, sizeof(payload), "{\"claimCode\":\"%s\"}", claimCode);

  String response;
  if (!postJson("/api/device/claim", payload, false, response)) {
    Serial.println("Claim request failed");
    return false;
  }

  JsonDocument doc;
  if (deserializeJson(doc, response)) return false;

  const char* newBoxId = doc["boxId"];
  const char* newKey = doc["deviceKey"];
  if (newBoxId == nullptr || newKey == nullptr) return false;

  strncpy(boxId, newBoxId, sizeof(boxId) - 1);
  boxId[sizeof(boxId) - 1] = '\0';
  strncpy(deviceKey, newKey, sizeof(deviceKey) - 1);
  deviceKey[sizeof(deviceKey) - 1] = '\0';
  needsClaim = false;
  claimCode[0] = '\0';

  // persist the claimed identity, clear the used-up claim code
  writeEeStr(CFG_BOXID_ADDR, boxId, (int)sizeof(boxId));
  writeEeStr(CFG_KEY_ADDR, deviceKey, (int)sizeof(deviceKey));
  writeEeStr(CFG_CLAIM_ADDR, "", (int)sizeof(claimCode));
  eeUpdate(CFG_NEED_CLAIM_ADDR, 0);
  eeCommit();

  Serial.println("Box claimed successfully");
  return true;
}

/**
 * All blocking network work lives on this task: /sync polling, queued
 * event reports, claim retries and Wi-Fi reconnects. The main loop task
 * stays free for the keypad and LCD, so no press ever waits on HTTPS.
 */
void networkTask(void*) {
  for (;;) {
    unsigned long now = millis();
    if (WiFi.status() == WL_CONNECTED) {
      if (needsClaim && now - lastClaimAttemptMs >= 30000UL) {
        lastClaimAttemptMs = now;
        if (tryClaim()) {
          netPushEvent(NET_EVENT_CLAIM_OK);
        } else {
          netPushEvent(NET_EVENT_CLAIM_FAILED);
        }
      }
      flushPendingEvents();
      // same heartbeat as the old loop: idle-only polling
      if (state == STATE_IDLE &&
          now - lastPollMs >= POLL_INTERVAL_MS &&
          now - lastKeyMs >= KEYPAD_QUIET_MS) {
        lastPollMs = now;
        pollSync();
      }
    } else {
      connectWiFi();
    }
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

// ---------- state machine actions ----------
void handleCorrectEntry() {
  // snapshot the codeId under the mutex, then flash first, RAM second:
  // the used codeId can never be lost.
  char usedCodeId[CODE_ID_LEN + 1];
  if (xSemaphoreTake(stateMutex, portMAX_DELAY) == pdTRUE) {
    strncpy(usedCodeId, activeCodeId, CODE_ID_LEN);
    usedCodeId[CODE_ID_LEN] = '\0';
    strncpy(pendingUsedCodeId, usedCodeId, CODE_ID_LEN);
    pendingUsedCodeId[CODE_ID_LEN] = '\0';
    xSemaphoreGive(stateMutex);
  }
  eepromAddCodeId(usedCodeId);
  clearCode();
  entryLen = 0;
  entry[0] = '\0';
  wrongCount = 0;

  unlockBolt();
  digitalWrite(PIN_GREEN, HIGH);
  digitalWrite(PIN_RED, LOW);
  beep(1200, 120);

  lcdShow("Correct passcode", "");
  delay(1600);
  lcdShow("Press # to lock", "");

  openedAtMs = millis();
  pendingUsed = true;
  state = STATE_OPEN;  // '#' locks again when the driver is done
}

void handleWrongEntry() {
  entryLen = 0;
  entry[0] = '\0';
  flashRed();
  beep(300, 400);
  lcdShow("Wrong passcode", "");
  pendingWrong = true;
  delay(1500);  // let the driver read the message
}

void lockBox() {
  // The driver closed the lid and pressed '#': lock the box again.
  lockBolt();
  digitalWrite(PIN_GREEN, LOW);
  beep(800, 200);
  lcdShow("Box locked", "");
  delay(2000);
  entryLen = 0;
  entry[0] = '\0';
  lcdShow("Enter Code", "");
  pendingClosed = true;
  state = STATE_IDLE;
}

void startLockout() {
  lockoutUntilMs = millis() + LOCKOUT_MS;
  wrongCount = 0;
  entryLen = 0;
  entry[0] = '\0';
  digitalWrite(PIN_RED, HIGH);
  digitalWrite(PIN_GREEN, LOW);
  lcdShow("Locked 30 sec", "");
  beep(250, 600);
  state = STATE_LOCKOUT;
}

void handleKey(char key) {
  lastKeyMs = millis();
  beep(2000, 20);

  if (state == STATE_OPEN) {
    // '#' locks the box again; ignored briefly after unlocking so the same
    // press that opened it can't immediately re-lock.
    if (key == '#' && millis() - openedAtMs > OPEN_GUARD_MS) lockBox();
    return;
  }

  if (key == '*') {  // clear
    entryLen = 0;
    entry[0] = '\0';
    if (state == STATE_KEYPAD) state = STATE_IDLE;
    lcdShow("Enter Code", "");
    return;
  }
  if (key == '#') {  // submit
    if (entryLen < CODE_LEN) {
      entryLen = 0;
      entry[0] = '\0';
      state = STATE_IDLE;
      lcdShow("Enter 6 digits", "");
      delay(1200);
      lcdShow("Enter Code", "");
      return;
    }
    if (activeCode[0] == '\0') {
      entryLen = 0;
      entry[0] = '\0';
      flashRed();
      lcdShow("No active code", "");
      state = STATE_IDLE;
      return;
    }
    bool submittedMatches = false;
    if (xSemaphoreTake(stateMutex, portMAX_DELAY) == pdTRUE) {
      submittedMatches = strcmp(entry, activeCode) == 0;
      xSemaphoreGive(stateMutex);
    }
    if (submittedMatches) {
      handleCorrectEntry();
    } else {
      wrongCount++;
      if (wrongCount >= MAX_WRONG_BEFORE_LOCKOUT) {
        startLockout();
      } else {
        handleWrongEntry();
        state = STATE_IDLE;
        lcdShow("Enter Code", "");
      }
    }
    return;
  }

  if (key < '0' || key > '9') return;  // ignore A, B, C, D
  if (entryLen >= CODE_LEN) return;
  entry[entryLen++] = key;
  entry[entryLen] = '\0';
  lcdShow("Enter Code", maskedEntry());
  if (state == STATE_IDLE) state = STATE_KEYPAD;
}

const char* maskedEntry() {
  static char dots[CODE_LEN + 1];
  for (byte i = 0; i < entryLen; i++) dots[i] = '*';
  dots[entryLen] = '\0';
  return dots;
}

// ---------- setup portal (production provisioning) ----------
String readClientLine(WiFiClient& client) {
  String line;
  unsigned long t0 = millis();
  while (millis() - t0 < 4000) {
    if (!client.available()) {
      delay(2);
      continue;
    }
    int ch = client.read();
    if (ch == -1) continue;
    if (ch == '\n') break;
    if (ch != '\r') line += (char)ch;
  }
  return line;
}

String urlDecode(const String& s) {
  String out;
  for (unsigned int i = 0; i < s.length(); i++) {
    char c = s[i];
    if (c == '+') {
      out += ' ';
    } else if (c == '%' && i + 2 < s.length()) {
      char hex[3] = {s[i + 1], s[i + 2], '\0'};
      out += (char)strtol(hex, NULL, 16);
      i += 2;
    } else {
      out += c;
    }
  }
  return out;
}

String formValue(const String& body, const char* key) {
  String needle = String(key) + "=";
  int start = body.indexOf(needle);
  if (start < 0) return "";
  start += needle.length();
  int end = body.indexOf('&', start);
  if (end < 0) end = body.length();
  return urlDecode(body.substring(start, end));
}

void sendHtml(WiFiClient& client, const char* content) {
  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: text/html");
  client.print("Content-Length: ");
  client.println(strlen(content));
  client.println("Connection: close");
  client.println();
  client.print(content);
}

void sendPortalPage(WiFiClient& client, const char* errorMsg) {
  char msg[96];
  msg[0] = '\0';
  if (errorMsg) {
    snprintf(msg, sizeof(msg), "<p style='color:red'>%s</p>", errorMsg);
  }

  char page[768];
  snprintf(page, sizeof(page),
           "<html><body style='font-family:sans-serif;max-width:400px;margin:"
           "20px auto'>"
           "<h3>SafeDrop setup</h3>%s"
           "<form method='POST' action='/save'>"
           "Wi-Fi name:<br><input name='ssid' required><br>"
           "Wi-Fi password:<br><input name='pass' type='password'><br>"
           "Claim code:<br><input name='claim' required "
           "style='text-transform:uppercase'><br><br>"
           "<input type='submit' value='Save and pair'>"
           "</form></body></html>",
           msg);

  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: text/html");
  client.print("Content-Length: ");
  client.println(strlen(page));
  client.println("Connection: close");
  client.println();
  client.print(page);
}

void handlePortalClient(WiFiClient client) {
  String req = readClientLine(client);  // e.g. "GET / HTTP/1.1"
  int contentLength = 0;
  while (true) {
    String line = readClientLine(client);
    if (line.length() == 0) break;
    if (line.startsWith("Content-Length:")) {
      contentLength = line.substring(15).toInt();
    }
  }

  String body;
  if (contentLength > 0 && contentLength < 512) {
    unsigned long t0 = millis();
    while ((int)body.length() < contentLength && millis() - t0 < 4000) {
      if (client.available()) body += (char)client.read();
    }
  }

  if (req.startsWith("POST /save")) {
    String ssid = formValue(body, "ssid");
    String pass = formValue(body, "pass");
    String code = formValue(body, "claim");
    code.toUpperCase();
    if (ssid.length() == 0 || ssid.length() > 32 ||
        pass.length() > 64 || code.length() < 6 || code.length() > 12) {
      sendPortalPage(client, "Check the Wi-Fi name and claim code.");
    } else {
      writeClaimConfig(ssid.c_str(), pass.c_str(), code.c_str());
      sendHtml(client,
               "<html><body style='font-family:sans-serif'><h3>Saved!</h3>"
               "<p>The box is rebooting to claim its key...</p></body></html>");
      delay(1500);
      ESP.restart();  // soft reset into normal mode
    }
  } else {
    sendPortalPage(client, NULL);
  }
  client.stop();
}

// Never returns: resets the board after a successful save.
void runSetupPortal() {
  lockBolt();
  digitalWrite(PIN_GREEN, LOW);
  digitalWrite(PIN_RED, HIGH);

  WiFi.mode(WIFI_AP);  // station off, access point on
  if (!WiFi.softAP(AP_SSID, AP_PASS)) {
    lcdShow("AP start failed", "");
    while (true) delay(1000);
  }
  setupServer.begin();
  Serial.println("Setup portal started");

  unsigned long lastLcd = 0;
  bool screen = false;
  while (true) {
    WiFiClient client = setupServer.accept();
    if (client) handlePortalClient(client);

    if (millis() - lastLcd > 3000) {
      lastLcd = millis();
      screen = !screen;
      if (screen) {
        lcdShow("AP: SafeDrop-Setup", "pw: safedrop123");
      } else {
        lcdShow("open in browser:", "http://192.168.4.1");
      }
    }
    delay(10);
  }
}

// ---------- setup / loop ----------
void setup() {
  Serial.begin(115200);
  EEPROM.begin(1024);  // highest used address is 602; NVS-backed

  // Reuse the TLS session between requests: a fresh handshake on every
  // 3 s poll blocked the loop for 1-2 s and dropped keypad presses.
  http.connectionKeepAlive();

  pinMode(PIN_GREEN, OUTPUT);
  pinMode(PIN_RED, OUTPUT);
  pinMode(PIN_BUZZER, OUTPUT);

  lockServo.setPeriodHertz(50);  // standard 50 Hz servo pulse
  lockServo.attach(PIN_SERVO, 500, 2400);
  lockBolt();

  Wire.begin(PIN_SDA, PIN_SCL);
  // Find the backpack: 0x27 (PCF8574) or 0x3F (PCF8574A) by default;
  // strap variants can land anywhere in 0x20-0x27 / 0x38-0x3F.
  byte lcdAddr = 0;
  for (byte a = 0x20; a <= 0x27 && lcdAddr == 0; a++) {
    Wire.beginTransmission(a);
    if (Wire.endTransmission() == 0) lcdAddr = a;
  }
  for (byte a = 0x38; a <= 0x3F && lcdAddr == 0; a++) {
    Wire.beginTransmission(a);
    if (Wire.endTransmission() == 0) lcdAddr = a;
  }
  if (lcdAddr == 0) {
    Serial.println("No I2C LCD backpack found — check VCC(5V)/GND and SDA->D21, SCL->D22");
  } else {
    Serial.print("LCD backpack found at 0x");
    Serial.println(lcdAddr, HEX);
    lcd = LiquidCrystal_I2C(lcdAddr, 16, 2);
  }
  lcd.init();
  lcd.backlight();
  lcdShow("SafeDrop", "Starting...");

  // Validate the server certificate on every HTTPS call (or opt out for
  // bench tests via ALLOW_INSECURE_TLS at the top of this file).
#ifdef ALLOW_INSECURE_TLS
  wifiClient.setInsecure();
#else
  wifiClient.setCACert(ROOT_CA);
#endif

  eepromInit();
  loadConfig();

  // Hold '*' (or the board's BOOT button) at power-on -> setup portal.
  // BOOT is on GPIO 0; hold it after reset, not during power-on (that
  // would drop the chip into the ROM download mode instead).
  pinMode(0, INPUT_PULLUP);
  lcdShow("Hold * or BOOT", "for setup mode");
  unsigned long t0 = millis();
  while (millis() - t0 < 5000) {
    if (keypad.getKey() == '*' || digitalRead(0) == LOW) {
      runSetupPortal();  // never returns
    }
    delay(10);
  }

  // Nothing configured at all -> setup portal
  if (wifiSsid[0] == '\0' ||
      (boxId[0] == '\0' && deviceKey[0] == '\0' && claimCode[0] == '\0')) {
    runSetupPortal();  // never returns
  }

  lcdShow("Connecting to", "Wi-Fi...");
  connectWiFi();
  if (needsClaim) {
    lcdShow("Claiming box...", claimCode);
    tryClaim();  // if it fails, the network task retries every 30 s
  }

  // Fast keypad scanning + off-loop network work start only now: the
  // setup-* window above still polls the keypad from the main context.
  stateMutex = xSemaphoreCreateMutex();
  netEventQueue = xQueueCreate(8, sizeof(int));
  xTaskCreatePinnedToCore(networkTask, "net", 8192, nullptr, 1, nullptr, 0);

  keyQueue = xQueueCreate(8, sizeof(char));
  xTaskCreatePinnedToCore(keypadScanTask, "keypad", 4096, nullptr, 1, nullptr, 0);

  lcdShow("Enter Code", "");
}

void loop() {
  unsigned long now = millis();

  // one-shot red LED flash
  if (redOffAtMs != 0 && now > redOffAtMs && state != STATE_LOCKOUT) {
    digitalWrite(PIN_RED, LOW);
    redOffAtMs = 0;
  }

  // network task -> UI events (server cleared the code, claim outcome)
  int evType;
  while (xQueueReceive(netEventQueue, &evType, 0) == pdTRUE) {
    if (evType == NET_EVENT_CODE_CLEARED) {
      lcdShow("Code cleared", "");
    } else if (evType == NET_EVENT_CLAIM_OK) {
      lcdShow("Box paired!", "");
      delay(1500);
      lcdShow("Enter Code", "");
    } else if (evType == NET_EVENT_CLAIM_FAILED) {
      lcdShow("Claim failed", "check code/expiry");
    }
  }

  // local TTL expiry (no RTC, so the countdown is millis()-based)
  bool codeExpired = false;
  if (xSemaphoreTake(stateMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
    codeExpired = activeCode[0] != '\0' && now > codeExpiresMs;
    xSemaphoreGive(stateMutex);
  }
  if (codeExpired) {
    clearCode();
    lcdShow("Code expired", "");
  }

  if (state == STATE_LOCKOUT) {
    char dump;
    while (xQueueReceive(keyQueue, &dump, 0) == pdTRUE) {
      // discard keys typed during lockout so none fire after it ends
    }
    if (now > lockoutUntilMs) {
      digitalWrite(PIN_RED, LOW);
      lcdShow("Enter Code", "");
      state = STATE_IDLE;
    }
    return;  // no keys, no polling during lockout
  }

  // keypad input (IDLE, KEYPAD and OPEN states) — served from the scan task
  char key;
  while (xQueueReceive(keyQueue, &key, 0) == pdTRUE) {
    handleKey(key);
  }
}
