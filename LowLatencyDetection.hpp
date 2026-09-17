/**
 * @file LowLatencyDetection.hpp
 * @brief Sub-microsecond Hardware Bit-Masking & Signal Classification Engine
 */

#ifndef LOW_LATENCY_DETECTION_HPP
#define LOW_LATENCY_DETECTION_HPP

#include <cstdint>

// 신호 무결성 상태 정의
enum class SignalIntegrity : uint8_t {
    VALID,          // 정상 생체 신호
    NOISE,          // 허용 범위 내의 순간적 전기 노이즈
    SPOOFED_ATTACK  // 전압 피싱 / 스푸핑 악성 신호
};

// 텔레메트리 결과 구조체
struct SignalTelemetry {
    uint16_t raw_adc;
    uint16_t processed_adc;
    SignalIntegrity integrity;
    int64_t latency_nanoseconds;
};

class LowLatencyDetector {
private:
    static constexpr uint16_t ECG_MIN_SAFE = 600;     // 최소 안전 전압
    static constexpr uint16_t ECG_MAX_SAFE = 3200;    // 최대 안전 전압
    static constexpr uint16_t ATTACK_THRESHOLD = 3800; // 피싱 공격 임계값

public:
    LowLatencyDetector() = default;

    /**
     * @brief Inline Assembly 기반 Raw ADC 레지스터 12-bit 비트 마스킹 (0x0FFF)
     */
    [[nodiscard]] static inline uint16_t parse_adc_register(uint16_t raw_value) noexcept {
        uint16_t masked_value = 0;
#if defined(__x86_64__) || defined(_M_X64)
        __asm__ volatile (
            "movw %1, %%ax \n\t"
            "andw $0x0FFF, %%ax \n\t"
            "movw %%ax, %0 \n\t"
            : "=r" (masked_value)
            : "r" (raw_value)
            : "%ax"
        );
#else
        masked_value = raw_value & 0x0FFF;
#endif
        return masked_value;
    }

    /**
     * @brief 신호 무결성 판별
     */
    [[nodiscard]] inline SignalIntegrity evaluate(uint16_t adc) const noexcept {
        if (adc >= ATTACK_THRESHOLD) {
            return SignalIntegrity::SPOOFED_ATTACK;
        }
        if (adc < ECG_MIN_SAFE || adc > ECG_MAX_SAFE) {
            return SignalIntegrity::NOISE;
        }
        return SignalIntegrity::VALID;
    }
};

#endif // LOW_LATENCY_DETECTION_HPP
