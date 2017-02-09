#include <string>
#include <algorithm>

#include <tins/radiotap.h>
#include <tins/dot11.h>
#include <tins/rsn_information.h>

#include "info.hpp"

template<typename String>
static auto ToUpper(String&& str) {
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

void ApInfo::Change(const Tins::Dot11Beacon& beacon,
                    const Tins::RadioTap& tap) {
    const auto freq = tap.channel_freq();
    const auto&& ssid = beacon.ssid();

    if (bssid_.empty()) {
        bssid_ = ToUpper(beacon.addr2().to_string());
    }
    power_ = tap.dbm_signal();
    ++beacons_;
    channel_ = freq == 2484 ? 14 : freq % 2412 / 5 + 1;
    mb_;
    enc_;
    essid_ = ssid.empty() ? "<length:  0>" : ssid;

    const auto pairwise_cyphers = beacon.rsn_information().pairwise_cyphers();
    if (!pairwise_cyphers.empty()) {
        switch (pairwise_cyphers[0]) {
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
            cipher_ = "WEP";
            break;
        default:
            cipher_ = "?";
            break;
        }
    }

    const auto akm_cyphers = beacon.rsn_information().akm_cyphers();
    if (!akm_cyphers.empty()) {
        switch (akm_cyphers[0]) {
        case Tins::RSNInformation::PMKSA:
            auth_ = "PMKSA";
            break;
        case Tins::RSNInformation::PSK:
            auth_ = "PSK";
            break;
        default:
            auth_ = "?";
            break;
        }
    }
}

void ApInfo::Change(const Tins::Dot11Data& data) {
    ++data_;
    per_second_;
}

void ConnectionInfo::Change(const Tins::Dot11AssocResponse& assoc_resp,
                            const Tins::RadioTap& tap) {
    if (bssid_.empty()) {
        bssid_ = ToUpper(assoc_resp.addr2().to_string());
    }
    station_ = assoc_resp.addr1().to_string();
    power_ = tap.dbm_signal();
    rate_ = rate_ex_.first + "-" + rate_ex_.second;
    lost_;
    ++frames_;
    probe_ = assoc_resp.ssid();
}
