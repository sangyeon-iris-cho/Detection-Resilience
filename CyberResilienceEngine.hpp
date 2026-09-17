/**
 * @file CyberResilienceEngine.hpp
 * @brief Zero-Downtime Safe-Fail State Machine & Synthetic Fallback Manager
 */

#ifndef CYBER_RESILIENCE_ENGINE_HPP
#define CYBER_RESILIENCE_ENGINE_HPP

#include "LowLatencyDetection.hpp"
#include <chrono>
#include <atomic>

enum class OperatingState : uint8_t {
    NORMAL_OPERATION,  // 정상 주회로 가동
    SAFE_FAIL_MODE     // 합성 백업 신호 가동 (Zero-Downtime)
};

class CyberResilienceEngine {
private:
    LowLatencyDetector detector;
    std::atomic<OperatingState> current_state{OperatingState::NORMAL_OPERATION};
    uint32_t consecutive_noise_count{0};
    uint64_t total_processed_packets{0};
    uint64_t total_attacks_mitigated{0};

    // 백업 모드용 안전 기준 전압(1500mV) 생성
    [[nodiscard]] inline uint16_t generate_safe_synthetic_signal() const noexcept {
        return 1500; 
    }

public:
    CyberResilienceEngine() = default;

    /**
     * @brief 실시간 신호 파이프라인 처리 및 Safe-Fail 복구
     */
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
                    // 신호가 안정화되면 정상 모드로 자가 복구 (Self-Healing)
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

#endif // CYBER_RESILIENCE_ENGINE_HPP
