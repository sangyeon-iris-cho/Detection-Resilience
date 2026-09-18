# Detection-Resilience
WELCOME. An honor to have you here, reading my document. <br>
This serves as the design overview and proposal for my project. <br>
<br>
**Background**: <br>
If you have interest in cybersecurity, you've likely heard that one of the most common ways to detect an intrusion is by analyzing suspicious logs, packets, or signals. <br>
However, there are critical systems out there where even a sudden, minor distortion in these signals can lead to catastrophic failure:<br>
* Say if a financial exchange approves suspicious transactions without filtering them?
* What if a patient's MRI machine or life-support system suddenly glitches during operation?<br>
These threats aren't confined to upper-layer network traffic; They can happen at the hardware level, especially when an attacker can physically access to the circuit - by injecting voltage glitches or spoofed signal pulses directly into the line.<br>
<br>
**Objectives**: <br>
This project looks beyond software-level network attacks to target hardware-level vulnerabilities. It is built to detect subtle malicious signals at the ADC(Analog-to-Digital Converter) / Sensor stage with ultra-low latency. <br>
In safety-critical environments like high-frequency finance and medical tech, even micro-signal anomalies must be recognized instantly without nano or microsecond delays. To eliminate the execution overhead in higher-level managed languages, this engine is implemented using C++20 and Inline Assembly(0x86-64), checking whether the signal's integrity is broken or not by verifying it via direct register-level bitwise operations.<br>
When an attack occurs, analyzing the vector or tracing the attacker isn't the most immediate priority-preventing the following, immediate damage is!
* If a financial exchange server, where millions of dollars are traded every second, suddenly halts due to a threat? Clients face massive financial damage, and would blame the company.
* Even worse: what if a life-support system shuts down the moment it senses an anomaly? Don't even want to think about that.<br>
Therefore, this engine rather focuses on preventing immediate and irreversible harm, instead of prioritizing post-attack forensics. The system automatically:
* Isolates the detected malicious signal instantly
* Then, change it to a safe synthetic-backup mode without dropping a single CPU cycle.<br>
By shifting focus from static defense to active resilience, the engine brings system downtime down to zero.<br>
<br>
**Performance Result**: <br>




<br>
<br>
Check how Dependency Injection and parse_fast() and evaluate() is utilized from the injected parser. Illustration using the code is below: <br> 
#ifndef HARDWARE_CYBER_RESILIENCE_ENGINE_HPP <br> 
#define HARDWARE_CYBER_RESILIENCE_ENGINE_HPP <br> 
 <br> 
#include "BaseCyberResilienceEngine.hpp" <br> 
#include "LowLatencyDetection.hpp" // Parser 접근 <br> 
 <br> 
class HardwareCyberResilienceEngine : public BaseCyberResilienceEngine { <br> 
private: <br> 
    std::unique_ptr<BaseLowLatencyParser> parser; <br> 
 <br> 
public: <br> 
    explicit HardwareCyberResilienceEngine(std::unique_ptr<BaseLowLatencyParser> p) <br> 
        : parser(std::move(p)) {} <br> 
 <br> 
    uint64_t process_pipeline(uint64_t raw_input) override { <br> 
        // 1. Low-Latency bit-masking <br> 
        uint64_t parsed = parser->parse_fast(raw_input); <br> 
         <br> 
        // 2. Integrity evaluation <br> 
        SignalIntegrity status = parser->evaluate(parsed); <br> 
 <br> 
        // 3. Fallback logic if attacked/noise <br> 
        if (status != SignalIntegrity::VALID) { <br> 
            return generate_safe_fallback_signal(); // 부모/자식의 Safe-fail 값 리턴 <br> 
        } <br> 
        return parsed; <br> 
    } <br> 
 <br> 
protected: <br> 
    uint64_t generate_safe_fallback_signal() const noexcept override { <br> 
        return 1500; // 하드웨어 안전 기본 전압 (1500mV) <br> 
    } <br> 
}; <br> 
 <br> 
#endif <br> 
