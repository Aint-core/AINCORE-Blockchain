#include "aincore_iot.h"
#include <cstdlib>
#include <ctime>

namespace AincoreIoT {

Device::Device(std::string id, std::string key)
    : device_id(id), private_key(key) {
  std::srand(std::time(0));
}

SensorData Device::readSensors() {
  SensorData data;
  // Simulate 20 data points
  for (int i = 0; i < 20; i++) {
    data.heart_rate.push_back(60 + (std::rand() % 20)); // 60-80 BPM
    data.breath_rate.push_back(12 + (std::rand() % 6)); // 12-18 BPM
  }
  data.spo2 = 95 + (std::rand() % 5); // 95-100%
  return data;
}

// #include <monocypher.h> // Requires Monocypher library

String Device::signData(const String &payload) {
  // Production Implementation using Ed25519
  // 1. Convert payload to bytes
  // 2. Sign using private_key

  /*
  uint8_t signature[64];
  uint8_t sk[32]; // Decode hex private key to bytes
  // ... hex decode logic ...
  crypto_sign(signature, sk, NULL, (const uint8_t*)payload.c_str(),
  payload.length());

  // Return hex string of signature
  return hex_encode(signature, 64);
  */

  // For prototype without linking external lib, we return a placeholder
  // that indicates where the real signature would go.
  // In a real deployment, uncomment the above and link monocypher.
  return "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadb"
         "eefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
}

String Device::createPayload(const SensorData &data) {
  std::stringstream ss;
  ss << "{";
  ss << "\"device_id\": \"" << device_id << "\",";
  ss << "\"sensors\": {";

  ss << "\"heart_rate\": [";
  for (size_t i = 0; i < data.heart_rate.size(); ++i) {
    ss << data.heart_rate[i];
    if (i < data.heart_rate.size() - 1)
      ss << ",";
  }
  ss << "],";

  ss << "\"breath_rate\": [";
  for (size_t i = 0; i < data.breath_rate.size(); ++i) {
    ss << data.breath_rate[i];
    if (i < data.breath_rate.size() - 1)
      ss << ",";
  }
  ss << "],";

  ss << "\"spo2\": " << data.spo2;
  ss << "},";

  // Sign the data so far (simplified)
  String signature = signData(ss.str());
  ss << "\"signature\": \"" << signature << "\"";
  ss << "}";

  return ss.str();
}
} // namespace AincoreIoT

// Example Main for testing C++ SDK
#ifndef ARDUINO
int main() {
  AincoreIoT::Device myWatch("watch_01", "priv_key_secret");
  AincoreIoT::SensorData data = myWatch.readSensors();
  std::string payload = myWatch.createPayload(data);

  std::cout << "Generated Payload:" << std::endl;
  std::cout << payload << std::endl;
  return 0;
}
#endif
