#include <string>
#include <memory>

#include <tins/dot11.h>
#include <tins/sniffer.h>

#include "dot11sniff.hpp"

Dot11Sniffer::Dot11Sniffer(const std::string interface) {
    config_.set_promisc_mode(true);
    sniffer_ = std::make_unique<Tins::Sniffer>(interface, config_);
}

Tins::Dot11 Dot11Sniffer::NextDot11() {
    Tins::Dot11 dot11;
    
    sniffer_->sniff_loop([&dot11](Tins::PDU& pdu) {
        dot11 = pdu.rfind_pdu<Tins::Dot11>();
        return false;
    });
    
    return dot11;
}
