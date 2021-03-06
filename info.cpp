#include "info.hpp"

#include <tins/radiotap.h>
#include <tins/dot11.h>
#include <tins/rsn_information.h>
#include <tins/packet.h>
#include <tins/pdu.h>

#include <algorithm>
#include <chrono>

using namespace std;

template<typename String>
static String const ToUpper(String&& str) {
    transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

template<typename Type, typename Iter>
static Type FromIter(Iter const it) {
    return *reinterpret_cast<Type const *>(&*it);
}

static string ToStringFromRSN(Tins::RSNInformation::cyphers_type const& cyphers) {
    if (!cyphers.empty()) {
        switch (cyphers.front()) {
        case Tins::RSNInformation::WEP_40:
            return "WEP";
        case Tins::RSNInformation::TKIP:
            return "TKIP";
        case Tins::RSNInformation::CCMP:
            return "CCMP";
        case Tins::RSNInformation::WEP_104:
            return "WEP104";
        default:
            return "";
        }
    }
}

static string ToStringFromRSN(Tins::RSNInformation::akm_type const& akms) {
    if (!akms.empty()) {
        switch (akms.front()) {
        case Tins::RSNInformation::PMKSA:
            return "MGT";
        case Tins::RSNInformation::PSK:
            return "PSK";
        default:
            return "";
        }
    }
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

static string ToStringFromWPAUCS(uint32_t const ucs) {
    switch (ucs) {
    case WPAInformation::WEP_40:
        return "WEP";
    case WPAInformation::TKIP:
        return "TKIP";
    case WPAInformation::WRAP:
        return "WRAP";
    case WPAInformation::CCMP:
        return "CCMP";
    case WPAInformation::WEP_104:
        return "WEP104";
    default:
        return "";
    }
}

static string ToStringFromWPAAKM(uint32_t const akm) {
    switch (akm) {
    case WPAInformation::PMKSA:
        return "MGT";
    case WPAInformation::PSK:
        return "PSK";
    default:
        return "";
    }
}

void ApInfo::Update(Tins::Dot11Beacon const& beacon,
                    Tins::RadioTap const& tap) {
    ++beacons_;
    auto const freq = tap.channel_freq();
    auto const ssid = beacon.ssid();

    if (bssid_.empty())
        bssid_ = ToUpper(beacon.addr2().to_string());

    power_ = tap.dbm_signal();
    channel_ = freq == 2484 ? 14 : freq % 2412 / 5 + 1;
    essid_ = ssid.empty() ? "<length:  0>" : ssid;
    
    auto const raw = Tins::Packet{ beacon }.pdu()->serialize();
    if (beacon.capabilities().privacy()) {
        try {
            enc_ = "WPA2";
            
            auto const rsn = beacon.rsn_information();
            cipher_ = ToStringFromRSN(rsn.pairwise_cyphers());
            auth_ = ToStringFromRSN(rsn.akm_cyphers());
        }
        catch (Tins::option_not_found&) {
            decltype(raw) const wpa{ 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00 };
            auto const wpa_begin = search(raw.begin(), raw.end(), wpa.begin(), wpa.end());
            if (wpa_begin != raw.end()) {
                enc_ = "WPA";
                
                constexpr int kOuiSize = 4;
                decltype(raw) const oui{ 0x00, 0x50, 0xf2 };

                auto const mcs_begin = search(wpa_begin + wpa.size(), raw.end(), oui.begin(), oui.end());
                auto const mcs_end = mcs_begin + kOuiSize;
                
                auto const ucs_count = FromIter<uint16_t>(mcs_end); 
                auto const ucs_begin = search(mcs_end, raw.end(), oui.begin(), oui.end());
                auto const ucs_end = ucs_begin + kOuiSize * ucs_count;
                if (ucs_begin != raw.end())
                    cipher_ = ToStringFromWPAUCS(FromIter<uint32_t>(ucs_begin));
                
                auto const akm_begin = search(ucs_end, raw.end(), oui.begin(), oui.end());
                if (akm_begin != raw.end())
                    auth_ = ToStringFromWPAAKM(FromIter<uint32_t>(akm_begin));
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
        auto const extended_max_rate = beacon.extended_supported_rates().back();
        if (extended_max_rate > max_rate)
            max_rate = extended_max_rate;
    }
    catch (Tins::option_not_found&) {}
    
    decltype(raw) const qos{ 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01 };
    auto const mb_rate = static_cast<int>(max_rate);
    auto const mb_qos = search(raw.begin(), raw.end(), qos.begin(), qos.end()) != raw.end() ? 'e' : ' ';
    auto const mb_spa = beacon.capabilities().short_preamble() ? '.' : ' ';
    mb_ = to_string(mb_rate) + string{ mb_qos } + string{ mb_spa };
}

namespace {
int g_time_point;
}

void ApInfo::Update(Tins::Dot11Data const& data,
                    Tins::RadioTap const& tap) {
    ++data_;
    ++data_latest_;
    power_ = tap.dbm_signal();
    
    constexpr int kTime = 10;
    auto now = chrono::steady_clock::now().time_since_epoch().count();
    if (!g_time_point || now - g_time_point > kTime) {
        data_latest_ = 0;
        g_time_point = now;
    }
    per_second_ = data_latest_ / kTime;
}

void ConnectionInfo::Update(Tins::Dot11ProbeRequest const& probe_req,
                            Tins::RadioTap const& tap) {
    ++frames_;
    ApplyAddress(probe_req.addr1(), probe_req.addr2());
    UpdateRateFromStation(tap);
    
    power_ = tap.dbm_signal();
}

void ConnectionInfo::Update(Tins::Dot11ProbeResponse const& probe_resp,
                            Tins::RadioTap const& tap) {
    ++frames_;
    ApplyAddress(probe_resp.addr2(), probe_resp.addr1());
    UpdateRateFromAp(tap);
    
    power_ = tap.dbm_signal();
    if (probe_.empty())
        probe_ = probe_resp.ssid();
}

void ConnectionInfo::Update(Tins::Dot11Data const& data,
                            Tins::RadioTap const& tap) {
    ++frames_;
    ApplyAddress(data.addr1(), data.addr2());
    UpdateRateFromStation(tap);
    
    power_ = tap.dbm_signal();
    auto seq = data.seq_num();
    if (seq_last_) {
        auto const diff = seq - seq_last_ - 1;
        if(0 < diff && diff < 1000)
            lost_ += diff;
    }
    seq_last_ = seq;
}

void ConnectionInfo::ApplyAddress(Tins::Dot11::address_type const& bssid,
                                  Tins::Dot11::address_type const& station) {
    auto const kNotAssociated = "(not associated)";

    if (bssid_.empty()) {
        if (Tins::Dot11::BROADCAST == bssid)
            bssid_ = kNotAssociated;
        else
            bssid_ = ToUpper(bssid.to_string());
    }
    
    if (station_.empty())
        station_ = ToUpper(station.to_string());
}

void ConnectionInfo::UpdateRateFromStation(Tins::RadioTap const& tap) {
    try {
        rate_number_.second = tap.rate();
    }
    catch (Tins::field_not_present&) {
        return;
    }
    UpdateRateString();
}

void ConnectionInfo::UpdateRateFromAp(Tins::RadioTap const& tap) {
    try {
        rate_number_.first = tap.rate();
    }
    catch (Tins::field_not_present&) {
        return;
    }
    UpdateRateString();
}

void ConnectionInfo::UpdateRateString() {
    rate_ = to_string(rate_number_.first) + "-" + to_string(rate_number_.second);
}
