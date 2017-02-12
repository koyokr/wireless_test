#include <string>
#include <algorithm>

#include <tins/radiotap.h>
#include <tins/dot11.h>
#include <tins/rsn_information.h>
#include <tins/packet.h>
#include <tins/pdu.h>

#include "info.hpp"

template<typename String>
static auto ToUpper(String&& str) {
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

template<typename Type, typename Iter>
static Type FromIter(const Iter it) {
    return *reinterpret_cast<const Type *>(&*it);
}

static std::string ToStringFromRSN(const Tins::RSNInformation::cyphers_type& cyphers) {
    std::string str;
    if (!cyphers.empty()) {
        switch (cyphers.front()) {
        case Tins::RSNInformation::WEP_40:
            str = "WEP";
            break;
        case Tins::RSNInformation::TKIP:
            str = "TKIP";
            break;
        case Tins::RSNInformation::CCMP:
            str = "CCMP";
            break;
        case Tins::RSNInformation::WEP_104:
            str = "WEP104";
            break;
        default:
            break;
        }
    }
    return str;
}
static std::string ToStringFromRSN(const Tins::RSNInformation::akm_type& akms) {
    std::string str;
    if (!akms.empty()) {
        switch (akms.front()) {
            case Tins::RSNInformation::PMKSA:
                str = "MGT";
                break;
            case Tins::RSNInformation::PSK:
                str = "PSK";
                break;
            default:
                break;
        }
    }
    return str;
}

namespace WPAInformation {
enum CypherSuites {
    WEP_40  = 0x01f25000,
    TKIP    = 0x02f25000,
    WRAP    = 0x03f25000,
    CCMP    = 0x04f25000,
    WEP_104 = 0x05f25000
};
enum AKMSuites {
        PMKSA = 0x01f25000,
        PSK   = 0x02f25000
};
}
static std::string ToStringFromUCS(const uint32_t ucs) {
    std::string str;
    switch (ucs) {
    case WPAInformation::WEP_40:
        str = "WEP";
        break;
    case WPAInformation::TKIP:
        str = "TKIP";
        break;
    case WPAInformation::WRAP:
        str = "WRAP";
        break;
    case WPAInformation::CCMP:
        str = "CCMP";
        break;
    case WPAInformation::WEP_104:
        str = "WEP104";
        break;
    default:
        break;
    }
    return str;
}
static std::string ToStringFromAKM(const uint32_t akm) {
    std::string str;
    switch (akm) {
    case WPAInformation::PMKSA:
        str = "MGT";
        break;
    case WPAInformation::PSK:
        str = "PSK";
        break;
    default:
        break;
    }
    return str;
}

void ApInfo::Update(const Tins::Dot11Beacon& beacon,
                    const Tins::RadioTap& tap) {
    ++beacons_;
    const auto freq = tap.channel_freq();
    const auto ssid = beacon.ssid();

    if (bssid_.empty()) {
        bssid_ = ToUpper(beacon.addr2().to_string());
    }
    power_ = tap.dbm_signal();
    channel_ = freq == 2484 ? 14 : freq % 2412 / 5 + 1;
    essid_ = ssid.empty() ? "<length:  0>" : ssid;
    
    const auto raw = Tins::Packet{ beacon }.pdu()->serialize();
    if (beacon.capabilities().privacy()) {
        try {
            enc_ = "WPA2";
            
            const auto rsn = beacon.rsn_information();
            cipher_ = ToStringFromRSN(rsn.pairwise_cyphers());
            auth_ = ToStringFromRSN(rsn.akm_cyphers());
        }
        catch (Tins::option_not_found&) {
            const decltype(raw) wpa{ 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00 };
            const auto wpa_begin = std::search(raw.begin(), raw.end(),
                                               wpa.begin(), wpa.end());
            if (wpa_begin != raw.end()) {
                enc_ = "WPA";
                
                constexpr int kOuiSize = 4;
                const decltype(raw) oui{ 0x00, 0x50, 0xf2 };
                const auto mcs_begin = std::search(wpa_begin + wpa.size(), raw.end(),
                                                   oui.begin(), oui.end());
                const auto mcs_end = mcs_begin + kOuiSize;
                
                const auto ucs_count = FromIter<uint16_t>(mcs_end); 
                const auto ucs_begin = std::search(mcs_end, raw.end(),
                                                   oui.begin(), oui.end());
                const auto ucs_end = ucs_begin + kOuiSize * ucs_count;
                if (ucs_begin != raw.end()) {
                    cipher_ = ToStringFromUCS(FromIter<uint32_t>(ucs_begin));
                }
                
                const auto akm_begin = std::search(ucs_end, raw.end(),
                                                   oui.begin(), oui.end());
                if (akm_begin != raw.end()) {
                    auth_ = ToStringFromAKM(FromIter<uint32_t>(akm_begin));
                }
            }
            else { // not found wpa information
                cipher_ = enc_ = "WEP";
            }
        }
    }
    else { // 0 == privacy
        enc_ = "OPN";
    }
    
    auto max_rate = beacon.supported_rates().back();
    try {
        const auto extended_max_rate = beacon.extended_supported_rates().back();
        if (extended_max_rate > max_rate) {
            max_rate = extended_max_rate;
        }
    }
    catch (Tins::option_not_found&) {}
    
    const decltype(raw) qos{ 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01 };
    const auto mb_rate = static_cast<int>(max_rate);
    const auto mb_qos = std::search(raw.begin(), raw.end(),
                                    qos.begin(), qos.end()) != raw.end() ? 'e' : ' ';
    const auto mb_spa = beacon.capabilities().short_preamble() ? '.' : ' ';
    mb_ = std::to_string(mb_rate) + std::string{ mb_qos } + std::string{ mb_spa };
}

void ApInfo::Update(const Tins::Dot11Data& data,
                    const Tins::RadioTap& tap) {
    ++data_;
    power_ = tap.dbm_signal();
    
    per_second_;
}

void ConnectionInfo::Update(const Tins::Dot11ProbeRequest& probe_req,
                            const Tins::RadioTap& tap) {
    ++frames_;
    ApplyAddress(probe_req.addr1(), probe_req.addr2());
    UpdateRadioFromStation(tap);
}

void ConnectionInfo::Update(const Tins::Dot11ProbeResponse& probe_resp,
                            const Tins::RadioTap& tap) {
    ++frames_;
    ApplyAddress(probe_resp.addr2(), probe_resp.addr1());
    UpdateRadioFromAp(tap);
    
    if (probe_.empty()) {
        probe_ = probe_resp.ssid();
    }
}

void ConnectionInfo::Update(const Tins::Dot11Data& data,
                            const Tins::RadioTap& tap) {
    ++frames_;
    ApplyAddress(data.addr1(), data.addr2());
    UpdateRadioFromStation(tap);
    
    auto seq = data.seq_num();
    if (seq_last_ != 0) {
        auto diff = seq - seq_last_ - 1;
        if(diff > 0) {
            lost_ += diff;
        }
    }
    seq_last_ = seq;
}

void ConnectionInfo::ApplyAddress(const Tins::Dot11::address_type& bssid,
                                  const Tins::Dot11::address_type& station) {
    constexpr auto kNotAssociated = "(not associated)";
    
    if (Tins::Dot11::BROADCAST == bssid) {
        if (bssid_.empty()) {
            bssid_ = kNotAssociated;
        }
    }
    else if (bssid_.empty()) {
        bssid_ = ToUpper(bssid.to_string());
    }
    
    if (station_.empty()) {
        station_ = ToUpper(station.to_string());
    }
}

void ConnectionInfo::UpdateRadioFromStation(const Tins::RadioTap& tap) {
    try {
        rate_num_.second = tap.rate();
    }
    catch (Tins::field_not_present&) {}
    UpdateRadioAfter(tap);
}

void ConnectionInfo::UpdateRadioFromAp(const Tins::RadioTap& tap) {
    try {
        rate_num_.first = tap.rate();
    }
    catch (Tins::field_not_present&) {}
    UpdateRadioAfter(tap);
}

void ConnectionInfo::UpdateRadioAfter(const Tins::RadioTap& tap) {
    power_ = tap.dbm_signal();
    rate_ = std::to_string(rate_num_.first) + "-" + std::to_string(rate_num_.second);
}
