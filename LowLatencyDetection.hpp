// LowLatencyDetection.hpp
#ifndef LOW_LATENCY_DETECTION_HPP
#define LOW_LATENCY_DETECTION_HPP

#include <cstdint>

enum class SignalIntegrity : uint8_t {
    VALID,
    NOISE,
    SPOOFED_ATTACK
};

// 1. 추상 부모 클래스: Generic Low-Latency Interface
class BaseLowLatencyParser {
public:
    virtual ~BaseLowLatencyParser() = default;

    // 비트 마스킹 및 레지스터/패킷 파싱 (Inline/Assembly Optimization)
    [[nodiscard]] virtual uint64_t parse_fast(uint64_t raw_input) const noexcept = 0;

    // 무결성 검증 (Integrity Evaluation)
    [[nodiscard]] virtual SignalIntegrity evaluate(uint64_t parsed_value) const noexcept = 0;
};

// 2. 하드웨어 자식 클래스: 12-bit ADC & Register Bit-Masking
class HardwareADCParser : public BaseLowLatencyParser {
private:
    static constexpr uint16_t ADC_MIN_SAFE = 600;
    static constexpr uint16_t ADC_MAX_SAFE = 3200;
    static constexpr uint16_t ATTACK_THRESHOLD = 3800;

public:
    HardwareADCParser() = default;

    [[nodiscard]] uint64_t parse_fast(uint64_t raw_input) const noexcept override {
        uint16_t raw_adc = static_cast<uint16_t>(raw_input);
        uint16_t masked_value = 0;
#if defined(__x86_64__) || defined(_M_X64)
        __asm__ volatile (
            "movw %1, %%ax \n\t"
            "andw $0x0FFF, %%ax \n\t" // 12-bit ADC Register Masking (0x0FFF)
            "movw %%ax, %0 \n\t"
            : "=r" (masked_value)
            : "r" (raw_adc)
            : "%ax"
        );
#else
        masked_value = raw_adc & 0x0FFF;
#endif
        return static_cast<uint64_t>(masked_value);
    }

    [[nodiscard]] SignalIntegrity evaluate(uint64_t parsed_value) const noexcept override {
        uint16_t adc = static_cast<uint16_t>(parsed_value);
        if (adc >= ATTACK_THRESHOLD) {
            return SignalIntegrity::SPOOFED_ATTACK;
        }
        if (adc < ADC_MIN_SAFE || adc > ADC_MAX_SAFE) {
            return SignalIntegrity::NOISE;
        }
        return SignalIntegrity::VALID;
    }
};

// 3. 네트워크 자식 클래스: CAN Bus / Ethernet Packet Bit-Masking
class NetworkPacketParser : public BaseLowLatencyParser {
private:
    static constexpr uint64_t CAN_PAYLOAD_MASK = 0x0000FFFFFFFF0000ULL; // Payload 마스킹
    static constexpr uint64_t KNOWN_SPOOF_PATTERN = 0xDEAD0000;

public:
    NetworkPacketParser() = default;

    [[nodiscard]] uint64_t parse_fast(uint64_t raw_packet) const noexcept override {
        uint64_t payload = 0;
#if defined(__x86_64__) || defined(_M_X64)
        // 64-bit 레지스터(rax)를 사용한 Ultra-Fast Packet Header Extraction
        __asm__ volatile (
            "movq %1, %%rax \n\t"
            "shrq $16, %%rax \n\t"        // Shift to align payload
            "andq $0xFFFF, %%rax \n\t"    // Extract 16-bit payload
            "movq %%rax, %0 \n\t"
            : "=r" (payload)
            : "r" (raw_packet)
            : "%rax"
        );
#else
        payload = (raw_packet >> 16) & 0xFFFF;
#endif
        return payload;
    }

    [[nodiscard]] SignalIntegrity evaluate(uint64_t parsed_payload) const noexcept override {
        if (parsed_payload == 0xDEAD || parsed_payload > 9000) {
            return SignalIntegrity::SPOOFED_ATTACK;
        }
        if (parsed_payload < 100 || parsed_payload > 8000) {
            return SignalIntegrity::NOISE;
        }
        return SignalIntegrity::VALID;
    }
};

#endif
