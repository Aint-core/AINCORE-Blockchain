#ifndef AINCORE_IOT_H
#define AINCORE_IOT_H

#include <string>
#include <vector>

// Mocking Arduino types for generic C++ compatibility
#ifndef ARDUINO
    #include <iostream>
    #include <sstream>
    typedef std::string String;
#endif

namespace AincoreIoT {

    struct SensorData {
        std::vector<int> heart_rate;
        std::vector<int> breath_rate;
        int spo2;
    };

    class Device {
    private:
        std::string private_key;
        std::string device_id;

    public:
        Device(std::string id, std::string key);

        // Simulate reading from sensors
        SensorData readSensors();

        // Create a signed JSON payload
        String createPayload(const SensorData& data);

    private:
        // Mock signature function
        String signData(const String& payload);
    };

}

#endif
