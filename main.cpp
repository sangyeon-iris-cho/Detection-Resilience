#include <iostream>
#include <memory>

// 1. Low-Latency 파서 헤더
#include "LowLatencyDetection.hpp"

// 2. Resilience Engine 헤더들 (반드시 접근/include 해야 함!)
#include "HardwareCyberResilienceEngine.hpp"
#include "NetworkCyberResilienceEngine.hpp"

int main() {
    // -------------------------------------------------------------
    // A. 하드웨어 트랙 (HW Parser + HW Resilience Engine)
    // -------------------------------------------------------------
    std::cout << "=== 1. HARDWARE ADC TRACK ===\n";
    
    // Low-Latency HW Parser 생성
    auto hw_parser = std::make_unique<HardwareADCParser>();
    
    // HW Cyber Resilience Engine 생성 (Parser 주입)
    HardwareCyberResilienceEngine hw_engine(std::move(hw_parser));

    uint16_t raw_adc_glitch = 0x3EFF; // 3967 (Attack Threshold 초과 신호)
    uint64_t hw_out = hw_engine.process_pipeline(raw_adc_glitch);
    std::cout << "HW Recovered Signal: " << hw_out << " mV\n\n";

    // -------------------------------------------------------------
    // B. 네트워크 트랙 (NW Parser + NW Resilience Engine)
    // -------------------------------------------------------------
    std::cout << "=== 2. NETWORK CAN BUS TRACK ===\n";
    
    // Low-Latency NW Parser 생성
    auto net_parser = std::make_unique<NetworkPacketParser>();
    
    // NW Cyber Resilience Engine 생성 (Parser 주입)
    NetworkCyberResilienceEngine net_engine(std::move(net_parser));

    uint64_t raw_can_packet = 0x0000DEAD00001234ULL; // Spoofed Payload
    uint64_t net_out = net_engine.process_pipeline(raw_can_packet);
    std::cout << "Network Recovered Payload: " << net_out << "\n";

    return 0;
}
