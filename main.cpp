/**
 * @file main.cpp
 * @brief Main Execution Testbench for Embedded Cyber Resilience Engine
 */

#include "CyberResilienceEngine.hpp"
#include <iostream>
#include <array>
#include <iomanip>
#include <string>

int main() {
    CyberResilienceEngine engine;

    // 가상 ADC 하드웨어 버스 데이터 스트림
    // (정상 -> 노이즈 2회 -> 피싱 공격 2회 -> 정상 복귀)
    const std::array<uint16_t, 8> raw_bus_stream = {
        0x04B0, // 1200 (Valid)
        0x0514, // 1300 (Valid)
        0x012C, //  300 (Noise 1)
        0x0190, //  400 (Noise 2 -> Safe-Fail Trigger)
        0x0FFF, // 4095 (Spoofed Attack -> Immediate Safe-Fail)
        0x0F40, // 3904 (Spoofed Attack)
        0x0500, // 1280 (Valid -> Self Healing)
        0x04E2  // 1250 (Valid)
    };

    std::cout << "============================================================================\n";
    std::cout << " SIEMENS HEALTHINEERS TARGET: EMBEDDED CYBER RESILIENCE ENGINE\n";
    std::cout << " C++20 & x86-64 Inline Assembly Anomaly Detection Testbench\n";
    std::cout << "============================================================================\n\n";

    std::cout << std::left 
              << std::setw(12) << "[Raw Hex]"
              << std::setw(14) << "[Output ADC]"
              << std::setw(18) << "[Integrity]"
              << std::setw(22) << "[System State]"
              << std::setw(15) << "[Latency]" << "\n";
    std::cout << "----------------------------------------------------------------------------\n";

    for (uint16_t raw_signal : raw_bus_stream) {
        SignalTelemetry telemetry = engine.process_packet(raw_signal);

        std::string integrity_str;
        switch (telemetry.integrity) {
            case SignalIntegrity::VALID:          integrity_str = "VALID"; break;
            case SignalIntegrity::NOISE:          integrity_str = "NOISE_FILTERED"; break;
            case SignalIntegrity::SPOOFED_ATTACK: integrity_str = "ATTACK_SPOOFED"; break;
        }

        std::string state_str = (engine.get_current_state() == OperatingState::NORMAL_OPERATION) 
                                ? "NORMAL_MODE" 
                                : "SAFE_FAIL_FALLBACK";

        std::cout << std::hex << "0x" << std::setw(8) << std::setfill('0') << telemetry.raw_adc << std::setfill(' ') << std::dec
                  << std::setw(14) << telemetry.processed_adc
                  << std::setw(18) << integrity_str
                  << std::setw(22) << state_str
                  << std::setw(8) << telemetry.latency_nanoseconds << " ns\n";
    }

    std::cout << "----------------------------------------------------------------------------\n";
    std::cout << " [SUMMARY] Total Packets: " << engine.get_total_packets() 
              << " | Attacks Mitigated: " << engine.get_mitigated_attacks() << "\n";
    std::cout << "============================================================================\n";

    return 0;
}
