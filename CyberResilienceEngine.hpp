// Zero-Downtime Safe-Fail State Machine & Synthetic Fallback Manager

#ifndef CYBER_RESILIENCE_ENGINE_HPP
#define CYBER_RESILIENCE_ENGINE_HPP

#include "LowLatencyDetection.hpp"
#include <chrono>
#include <atomic>

enum class OperatingState : uint8_t {
    NORMAL_OPERATION,  // to operate the general circuit, when no attack is done.
    SAFE_FAIL_MODE     // synthetic backup circuit for Zero-Downtime
};

class CyberResilienceEngine {
private:
    LowLatencyDetector detector;
    std::atomic<OperatingState> current_state{OperatingState::NORMAL_OPERATION};
    uint32_t consecutive_noise_count{0};
    uint64_t total_processed_packets{0};
    uint64_t total_attacks_mitigated{0};

    // 1500mV is the safe standard. if attack happened, set the SAFE_FAIL_MODE's safe voltage
    [[nodiscard]] inline uint16_t generate_safe_synthetic_signal() const noexcept {
        return 1500; //why 1500mV?: ADC is 12bit, input ranging from 0~2^12 = 4095. 1500mV is located at the middle, safe and sound, solid :)
    }

public:
    CyberResilienceEngine() = default;

    // Signal Pipeline & SAFE_FAIL_MODE
    SignalTelemetry process_packet(uint16_t raw_packet) noexcept {
        const auto start_time = std::chrono::high_resolution_clock::now();

        // 1. Low-Level Assembly Parsing
        const uint16_t parsed_adc = LowLatencyDetector::parse_adc_register(raw_packet);

        // 2. Classify Signal Integrity
        const SignalIntegrity integrity = detector.evaluate(parsed_adc);

        // 3. Cyber Resilience Decision
        uint16_t final_adc_output = parsed_adc;

        switch (integrity) {
            case SignalIntegrity::VALID:
                consecutive_noise_count = 0;
                if (current_state.load(std::memory_order_relaxed) == OperatingState::SAFE_FAIL_MODE) {
                    // if relaxed, meaning the signal is back to normal, make the system to SAFE_FAIL_MODE (Self-Healing)
                    current_state.store(OperatingState::NORMAL_OPERATION, std::memory_order_relaxed);
                }
                break;

            case SignalIntegrity::NOISE:
                consecutive_noise_count++;
                if (consecutive_noise_count >= 2) {
                    current_state.store(OperatingState::SAFE_FAIL_MODE, std::memory_order_relaxed);
                    final_adc_output = generate_safe_synthetic_signal();
                }
                break;

            case SignalIntegrity::SPOOFED_ATTACK:
                total_attacks_mitigated++;
                current_state.store(OperatingState::SAFE_FAIL_MODE, std::memory_order_relaxed);
                final_adc_output = generate_safe_synthetic_signal();
                break;
        }

        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();

        total_processed_packets++;

        return SignalTelemetry{
            .raw_adc = raw_packet,
            .processed_adc = final_adc_output,
            .integrity = integrity,
            .latency_nanoseconds = latency
        };
    }

    [[nodiscard]] OperatingState get_current_state() const noexcept {
        return current_state.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t get_total_packets() const noexcept { return total_processed_packets; }
    [[nodiscard]] uint64_t get_mitigated_attacks() const noexcept { return total_attacks_mitigated; }
};

#endif 
