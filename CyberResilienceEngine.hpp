// GeneralCyberResilienceEngine.hpp
#ifndef GENERAL_CYBER_RESILIENCE_ENGINE_HPP
#define GENERAL_CYBER_RESILIENCE_ENGINE_HPP

#include <chrono>
#include <atomic>
#include <cstdint>

enum class OperatingState : uint8_t {
    NORMAL_OPERATION,
    SAFE_FAIL_MODE
};

enum class DataIntegrity : uint8_t {
    VALID,
    NOISE,
    SPOOFED_ATTACK
};

// 하드웨어/네트워크 공통 Generic Telemetry 구조체
struct GenericTelemetry {
    uint64_t raw_payload;
    uint64_t processed_payload;
    DataIntegrity integrity;
    int64_t latency_nanoseconds;
};

// Abstract Base Class: 상태 머신 및 Resilience 아키텍처 담당
class BaseCyberResilienceEngine {
protected:
    std::atomic<OperatingState> current_state{OperatingState::NORMAL_OPERATION};
    uint32_t consecutive_noise_count{0};
    uint64_t total_processed_units{0};
    uint64_t total_attacks_mitigated{0};

    // [자식 클래스 구현 필수] 도메인별 데이터 파싱 및 검증
    virtual DataIntegrity evaluate_integrity(uint64_t raw_input, uint64_t& parsed_output) = 0;
    
    // [자식 클래스 구현 필수] Safe-Fail 모드 시 대체할 데이터 생성
    virtual uint64_t generate_safe_fallback_signal() const noexcept = 0;

public:
    virtual ~BaseCyberResilienceEngine() = default;

    // 공통 Signal/Packet Pipeline (템플릿 메서드 패턴)
    GenericTelemetry process_data(uint64_t raw_input) noexcept {
        const auto start_time = std::chrono::high_resolution_clock::now();

        uint64_t parsed_payload = raw_input;
        const DataIntegrity integrity = evaluate_integrity(raw_input, parsed_payload);
        uint64_t final_output = parsed_payload;

        switch (integrity) {
            case DataIntegrity::VALID:
                consecutive_noise_count = 0;
                if (current_state.load(std::memory_order_relaxed) == OperatingState::SAFE_FAIL_MODE) {
                    current_state.store(OperatingState::NORMAL_OPERATION, std::memory_order_relaxed);
                }
                break;

            case DataIntegrity::NOISE:
                consecutive_noise_count++;
                if (consecutive_noise_count >= 2) {
                    current_state.store(OperatingState::SAFE_FAIL_MODE, std::memory_order_relaxed);
                    final_output = generate_safe_fallback_signal();
                }
                break;

            case DataIntegrity::SPOOFED_ATTACK:
                total_attacks_mitigated++;
                current_state.store(OperatingState::SAFE_FAIL_MODE, std::memory_order_relaxed);
                final_output = generate_safe_fallback_signal();
                break;
        }

        const auto end_time = std::chrono::high_resolution_clock::now();
        const auto latency = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();

        total_processed_units++;

        return GenericTelemetry{
            .raw_payload = raw_input,
            .processed_payload = final_output,
            .integrity = integrity,
            .latency_nanoseconds = latency
        };
    }

    [[nodiscard]] OperatingState get_current_state() const noexcept {
        return current_state.load(std::memory_order_relaxed);
    }
};

#endif
