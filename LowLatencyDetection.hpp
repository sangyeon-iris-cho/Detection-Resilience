// brief Sub-microsecond Hardware Bit-Masking & Signal Classification Engine

#ifndef LOW_LATENCY_DETECTION_HPP
#define LOW_LATENCY_DETECTION_HPP

#include <cstdint>

// defining the signal's integrity / validation
enum class SignalIntegrity : uint8_t {
    VALID,          // normal, valid signal
    NOISE,          // an electric noise, made suddenly, but ain't malicious
    SPOOFED_ATTACK  // malicious signal: an attack!!!
};

// result
struct SignalTelemetry {
    uint16_t raw_adc;
    uint16_t processed_adc;
    SignalIntegrity integrity;
    int64_t latency_nanoseconds;
};

class LowLatencyDetector {
private:
    static constexpr uint16_t ECG_MIN_SAFE = 600;     // safe volatge's min
    static constexpr uint16_t ECG_MAX_SAFE = 3200;    // safe voltage's max value
    static constexpr uint16_t ATTACK_THRESHOLD = 3800; // threshold value that determine it's an attack

public:
    LowLatencyDetector() = default;

    // Inline Assembly made for Raw ADC register: 12bit masking(0x0FFF)
    [[nodiscard]] static inline uint16_t parse_adc_register(uint16_t raw_value) noexcept {
        // nodiscard: do not discard the function's return value -> we do not need to call this function outside
        // inline function: insert this function into where it was called -> no need to generate and destroy a stack frame for this function = function overhead successfully eliminated
        // noexcept: do not handle exception -> this might cause a problem?
        uint16_t masked_value = 0;
#if defined(__x86_64__) || defined(_M_X64)
        __asm__ volatile (
        //volatile: complier, do not optimize it. use this, my code
            "movw %1, %%ax \n\t"
            "andw $0x0FFF, %%ax \n\t" //and gate's function: masking, within a single CCL
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

/* instead of simply coding
    uint16_t maked_value = raw_value & 0x0FFF; a cpp code that the computer will automatically compile and inteprete it to assembly language(and, move, etc...)
    i wanted to directly use the register ax
    to not store the variable to the memory(RAM/stack) and call it -> since it takes microseconds for a couple of CPU cycles, which can cause latency

*/

    // determine signal's integrity
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

#endif
