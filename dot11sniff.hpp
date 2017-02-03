#ifndef DOT11SNIFF_HPP
#define DOT11SNIFF_HPP

#include <string>
#include <memory>

#include <tins/dot11.h>
#include <tins/sniffer.h>

class Dot11Sniffer {
public:
    Dot11Sniffer(const std::string interface);
    Tins::Dot11 NextDot11();
private:
    std::unique_ptr<Tins::Sniffer> sniffer_;
    Tins::SnifferConfiguration config_;
};

#endif // DOT11SNIFF_HPP
