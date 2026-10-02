// Vigilant ESP32 logger: USB-serial append-only log + read-only Wi-Fi viewer.
// Keeps the serial protocol of vigilant_logger.ino (record / DUMP / STATS) and
// adds a Wi-Fi access point with READ-ONLY pages. There is deliberately no
// web route that erases or modifies the log.

#include <Arduino.h>
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>

// --- Configuration: CHANGE THE PASSWORD before the demo (8+ characters) ---
const char* AP_SSID = "Vigilant_Logger";
const char* AP_PASS = "ChangeMe-Vigilant26";

const char* LOG_FILE = "/telemetry_logs.jsonl";
const size_t MIN_FREE_BYTES = 4096;

AsyncWebServer server(80);
bool fsOk = false;

void dumpLogs() {
  File f = LittleFS.open(LOG_FILE, FILE_READ);
  if (!f) { Serial.println("ERR: no log file yet"); return; }
  Serial.println("---BEGIN LOG---");
  uint8_t buf[128];
  while (f.available()) {
    size_t n = f.read(buf, sizeof(buf));
    Serial.write(buf, n);
  }
  Serial.println("---END LOG---");
  f.close();
}

void setupWeb() {
  // Dashboard
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    String html = "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>";
    html += "<style>body{font-family:Arial;margin:40px;background:#121212;color:#fff}";
    html += "a{display:block;width:220px;padding:15px;margin-bottom:10px;background:#007bff;color:#fff;";
    html += "text-align:center;text-decoration:none;border-radius:5px}</style></head><body>";
    html += "<h2>Vigilant Hardware Logger</h2>";
    html += "<p>Flash used: " + String((unsigned)LittleFS.usedBytes()) + " / " + String((unsigned)LittleFS.totalBytes()) + " bytes</p>";
    html += "<a href=\"/logs\">View logs (raw)</a>";
    html += "<a href=\"/download\">Download JSONL</a>";
    html += "<p>Read-only: logs cannot be erased from this page.</p>";
    html += "</body></html>";
    request->send(200, "text/html", html);
  });

  // View in browser
  server.on("/logs", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (fsOk && LittleFS.exists(LOG_FILE)) request->send(LittleFS, LOG_FILE, "text/plain");
    else request->send(404, "text/plain", "No logs found in flash memory.");
  });

  // Download as a file
  server.on("/download", HTTP_GET, [](AsyncWebServerRequest *request) {
    if (fsOk && LittleFS.exists(LOG_FILE)) {
      AsyncWebServerResponse *response = request->beginResponse(LittleFS, LOG_FILE, "application/json");
      response->addHeader("Content-Disposition", "attachment; filename=\"telemetry_logs.jsonl\"");
      request->send(response);
    } else {
      request->send(404, "text/plain", "No logs found in flash memory.");
    }
  });

  server.begin();
}

void setup() {
  Serial.setRxBufferSize(1024);
  Serial.begin(115200);
  Serial.setTimeout(2000);

  fsOk = LittleFS.begin(true);  // true = format on first boot

  // Access point only: no internet, max 2 connected devices
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 2);
  setupWeb();

  Serial.println(fsOk ? "READY: Vigilant ESP32 logger" : "ERR: LittleFS mount failed");
  Serial.print("AP: ");
  Serial.print(AP_SSID);
  Serial.print(" at http://");
  Serial.println(WiFi.softAPIP());
}

void loop() {
  if (!Serial.available()) return;
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line.length() == 0) return;

  if (!fsOk) { Serial.println("ERR: filesystem unavailable"); return; }

  if (line == "DUMP") { dumpLogs(); return; }
  if (line == "STATS") {
    Serial.printf("STATS: used=%u total=%u\n",
                  (unsigned)LittleFS.usedBytes(), (unsigned)LittleFS.totalBytes());
    return;
  }

  if (line[0] != '{') { Serial.println("ERR: unknown command"); return; }
  if (LittleFS.totalBytes() - LittleFS.usedBytes() < MIN_FREE_BYTES) {
    Serial.println("ERR: flash full");
    return;
  }
  File f = LittleFS.open(LOG_FILE, FILE_APPEND);
  if (!f) { Serial.println("ERR: open failed"); return; }
  f.println(line);
  f.close();
  Serial.println("ACK: saved to flash");
}
