#include "CyberResilienceEngine.hpp"
#include "LowLatencyDetection.hpp"

class HardwareADCEngine : public BaseCyberResilienceEngine {
private:
    LowLatencyDetector detector;

protected:
    DataIntegrity evaluate_integrity(uint64_t raw_input, uint64_t& parsed_output) override {
        // 1. x86 Inline Assembly 기반 ADC 레지스터 파싱
        uint16_t adc_val = LowLatencyDetector::parse_adc_register(static_cast<uint16_t>(raw_input));
        parsed_output = adc_val;

        // 2. 신호 무결성 검증
        SignalIntegrity hw_integrity = detector.evaluate(adc_val);
        return static_cast<DataIntegrity>(hw_integrity);
    }

    // HW 전용 1500mV (12-bit ADC 중간값) Safe Signal
    uint64_t generate_safe_fallback_signal() const noexcept override {
        return 1500; 
    }
};
