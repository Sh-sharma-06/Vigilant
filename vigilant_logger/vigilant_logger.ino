#include <Arduino.h>
#include <LittleFS.h>

const char* LOG_FILE = "/telemetry_logs.jsonl";
const size_t MIN_FREE_BYTES = 4096;
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

void setup() {
  Serial.setRxBufferSize(1024);
  Serial.begin(115200);
  Serial.setTimeout(2000);
  fsOk = LittleFS.begin(true);  // true = format on first boot
  Serial.println(fsOk ? "READY: Vigilant ESP32 logger" : "ERR: LittleFS mount failed");
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
  // Deliberately NO erase/delete command: the host can append and read, never wipe.

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
