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

void ApInfo::Change(const Tins::Dot11Beacon& beacon,
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
            const auto rsn = beacon.rsn_information();
            enc_ = "WPA2";
            
            const auto pairwise_cyphers = rsn.pairwise_cyphers();
            if (!pairwise_cyphers.empty()) {
                switch (pairwise_cyphers.front()) {
                case Tins::RSNInformation::WEP_40:
                    cipher_ = "WEP";
                    break;
                case Tins::RSNInformation::TKIP:
                    cipher_ = "TKIP";
                    break;
                case Tins::RSNInformation::CCMP:
                    cipher_ = "CCMP";
                    break;
                case Tins::RSNInformation::WEP_104:
                    cipher_ = "WEP104";
                    break;
                default:
                    break;
                }
            }

            const auto akm_cyphers = rsn.akm_cyphers();
            if (!akm_cyphers.empty()) {
                switch (akm_cyphers.front()) {
                case Tins::RSNInformation::PMKSA:
                    auth_ = "MGT";
                    break;
                case Tins::RSNInformation::PSK:
                    auth_ = "PSK";
                    break;
                default:
                    break;
                }
            }
        }
        catch (Tins::option_not_found&) {
            const decltype(raw) wpa{ 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00 };
            const auto wpa_beg = std::search(raw.begin(), raw.end(),
                                             wpa.begin(), wpa.end());
            if (wpa_beg != raw.end()) {
                enc_ = "WPA";
                const decltype(raw) mcs{ 0x00, 0x50, 0xf2 };
                const auto mcs_beg = std::search(wpa_beg + wpa.size(), raw.end(),
                                                 mcs.begin(), mcs.end());
                const auto mcs_end = mcs_beg + mcs.size();
                
                const auto ucs_cnt = *reinterpret_cast<const uint16_t *>(&mcs_end[0]); 
                const auto& ucs = mcs;
                const auto ucs_beg = std::search(mcs_end, raw.end(),
                                                 ucs.begin(), ucs.end());
                const auto ucs_end = ucs_beg + ucs.size() * ucs_cnt;
                if (ucs_beg != raw.end()) {
                    const auto ucs = *reinterpret_cast<const uint32_t *>(&ucs_beg[0]);
                    switch (ucs) {
                    case 0x01f25000:
                        cipher_ = "1";
                        break;
                    case 0x02f25000:
                        cipher_ = "TKIP";
                        break;
                    case 0x03f25000:
                        cipher_ = "3";
                        break;
                    case 0x04f25000:
                        cipher_ = "CCMP";
                        break;
                    default:
                        break;
                    }
                }
                
                // const auto akm_cnt = *reinterpret_cast<const uint16_t *>(&ucs_end[0]); 
                const auto& akm = ucs;
                const auto akm_beg = std::search(ucs_end, raw.end(),
                                                 akm.begin(), akm.end());
                if (akm_beg != raw.end()) {
                    const auto akm = *reinterpret_cast<const uint32_t *>(&akm_beg[0]);
                    switch (akm) {
                    case 0x01f25000:
                        auth_ = "MGT";
                        break;
                    case 0x02f25000:
                        auth_ = "PSK";
                        break;
                    default:
                        break;
                    }
                }
            }
            else {
                cipher_ = enc_ = "WEP";
            }
        }
    }
    else {
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

void ApInfo::Change(const Tins::Dot11Data& data,
                    const Tins::RadioTap& tap) {
    ++data_;
    power_ = tap.dbm_signal();
    
    per_second_;
}

void ConnectionInfo::Change(const Tins::Dot11ProbeResponse& probe_resp,
                            const Tins::RadioTap& tap) {
    ++frames_;
    ChangeAddress(probe_resp.addr2(), probe_resp.addr1());
    ChangeRadioFromStation(tap);
    
    probe_ = probe_resp.ssid();
}

void ConnectionInfo::Change(const Tins::Dot11ProbeRequest& probe_req,
                            const Tins::RadioTap& tap) {
    ++frames_;
    ChangeAddress(probe_req.addr1(), probe_req.addr2());
    ChangeRadioFromStation(tap);
    
    probe_ = probe_req.ssid();
}

void ConnectionInfo::Change(const Tins::Dot11Data& data,
                            const Tins::RadioTap& tap) {
    ++frames_;
    ChangeAddress(data.addr1(), data.addr2());
    ChangeRadioFromStation(tap);
    
    auto seq = data.seq_num();
    if (seq_last_ != 0) {
        auto diff = seq - seq_last_ - 1;
        if(diff > 0) {
            lost_ += diff;
        }
    }
    seq_last_ = seq;
}

void ConnectionInfo::ChangeAddress(const Tins::Dot11::address_type& bssid,
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

void ConnectionInfo::ChangeRadioFromStation(const Tins::RadioTap& tap) {
    try {
        rate_num_.second = tap.rate();
    }
    catch (Tins::field_not_present&) {}
    ChangeRadioAfter(tap);
}

void ConnectionInfo::ChangeRadioFromAp(const Tins::RadioTap& tap) {
    try {
        rate_num_.first = tap.rate();
    }
    catch (Tins::field_not_present&) {}
    ChangeRadioAfter(tap);
}

void ConnectionInfo::ChangeRadioAfter(const Tins::RadioTap& tap) {
    power_ = tap.dbm_signal();
    rate_ = std::to_string(rate_num_.first) + "-" + std::to_string(rate_num_.second);
}
