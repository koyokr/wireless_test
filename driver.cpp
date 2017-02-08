#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <queue>
#include <chrono>

#include <tins/sniffer.h>
#include <tins/radiotap.h>
#include <tins/dot11.h>
#include <tins/rsn_information.h>

#include "driver.hpp"
#include "cli.hpp"

namespace {
std::mutex g_mutex;
}

static void PrintInfo(const std::map<std::string, ApInfo>& aps,
                      const std::map<ConnectionInfoKey, ConnectionInfo>& connections,
                      std::atomic<bool>& stop) {
    using namespace std::literals::chrono_literals;

    std::stringstream msg;
    const std::string ap_row{
        "\n"
        "  BSSID            "
        "  PWR"
        "  Beacons  "
        "  #Data,"
        "  #/s"
        "  CH"
        "  MB  "
        "  ENC "
        "  CIPHER"
        "  AUTH"
        "  ESSID"
        "\n"
    };
    const std::string connection_row{
        "\n"
        "  BSSID            "
        "  STATION          "
        "  PWR   "
        "  Rate"
        "  Lost"
        "  Frames"
        "  Probe"
        "\n"
    };

    cli::NextScreen();
    while (!stop) {
        msg << ap_row;
        std::this_thread::sleep_for(50ms);
        {
            std::lock_guard<std::mutex> lock{ g_mutex };
            for (const auto& p : aps) {
                const auto& info = p.second;
                msg << std::left
                    << "  " << std::setw(17) << info.bssid
                    << std::right
                    << "  " << std::setw(3)  << info.power
                    << "  " << std::setw(7)  << info.beacons
                    << "  " << std::setw(7)  << info.data
                    << "  " << std::setw(4)  << info.per_second
                    << "  " << std::setw(2)  << info.channel
                    << std::left
                    << "  " << std::setw(4)  << info.mb
                    << "  " << std::setw(4)  << info.enc
                    << "  " << std::setw(6)  << info.cipher
                    << "  " << std::setw(4)  << info.auth
                    << std::internal
                    << "  " << info.essid << "\n";
            }
        }

        msg << connection_row;
        std::this_thread::sleep_for(50ms);
        {
            std::lock_guard<std::mutex> lock{ g_mutex };
            for (const auto& p : connections) {
                const auto& info = p.second;
                msg << std::left
                    << "  " << std::setw(17) << info.bssid
                    << "  " << std::setw(17) << info.station
                    << std::right
                    << "  " << std::setw(3)  << info.power
                    << "  " << std::setw(7)  << info.rate
                    << "  " << std::setw(4)  << info.lost
                    << "  " << std::setw(6)  << info.frames
                    << std::internal
                    << "  " << info.probe << "\n";
            }
        }

        msg << "\n";
        cli::Update(msg.str());
        msg.str(std::string{});
    }
}

static void ChangeApInfo(ApInfo& ap,
                         const Tins::RadioTap& tap,
                         const Tins::Dot11Beacon& beacon) {
    const auto freq = tap.channel_freq();
    const auto&& ssid = beacon.ssid();

    ap.bssid = beacon.addr2().to_string();
    ap.beacons = std::to_string(std::stoi(ap.beacons) + 1);
    ap.power = std::to_string(tap.dbm_signal());
    ap.channel = std::to_string(freq == 2484 ? 14 : freq % 2412 / 5 + 1);
    ap.mb;
    ap.enc;
    ap.essid = ssid.empty() ? "<length:  0>" : ssid;

    const auto pairwise_cyphers = beacon.rsn_information().pairwise_cyphers();
    if (!pairwise_cyphers.empty()) {
        switch (pairwise_cyphers[0]) {
        case Tins::RSNInformation::WEP_40:
            ap.cipher = "WEP";
            break;
        case Tins::RSNInformation::TKIP:
            ap.cipher = "TKIP";
            break;
        case Tins::RSNInformation::CCMP:
            ap.cipher = "CCMP";
            break;
        case Tins::RSNInformation::WEP_104:
            ap.cipher = "WEP";
            break;
        default:
            ap.cipher = "?";
            break;
        }
    }

    const auto akm_cyphers = beacon.rsn_information().akm_cyphers();
    if (!akm_cyphers.empty()) {
        switch (akm_cyphers[0]) {
        case Tins::RSNInformation::PMKSA:
            ap.auth = "PMKSA";
            break;
        case Tins::RSNInformation::PSK:
            ap.auth = "PSK";
            break;
        default:
            ap.auth = "?";
            break;
        }
    }
}
static void ChangeApInfo(ApInfo& ap,
                         const Tins::Dot11Data& data) {
    ap.data = std::to_string(std::stoi(ap.data) + 1);
    ap.per_second;
}

static void ChangeConnectionInfo(ConnectionInfo& connection,
                                 const Tins::RadioTap& tap,
                                 const Tins::Dot11AssocResponse& assoc_resp) {
        connection.bssid = assoc_resp.addr2().to_string();
        connection.station = assoc_resp.addr1().to_string();
        connection.power = std::to_string(tap.dbm_signal());
        connection.rate;
        connection.lost;
        connection.frames = std::to_string(std::stoi(connection.frames) + 1);
        connection.probe = assoc_resp.ssid();
}

//     change -> true
// not change -> false
static bool UpdateInfo(std::map<std::string, ApInfo>& aps,
                       std::map<ConnectionInfoKey, ConnectionInfo>& connections,
                       const Tins::RadioTap& tap) {
    const auto& dot = tap.rfind_pdu<Tins::Dot11>();
    const auto type = dot.type();

    if (Tins::Dot11::DATA == type) {
        const auto& data = dot.rfind_pdu<Tins::Dot11Data>();
        if (aps.find(data.addr1().to_string()) == aps.end()) {
            return false;
        }
        std::lock_guard<std::mutex> lock{ g_mutex };
        ChangeApInfo(aps[data.addr1().to_string()],
                     dot.rfind_pdu<Tins::Dot11Data>());
    }
    else if (Tins::Dot11::MANAGEMENT == type) {
        const auto& mgmt = dot.rfind_pdu<Tins::Dot11ManagementFrame>();

        switch (dot.subtype()) {
        case Tins::Dot11::ASSOC_RESP: {
            std::lock_guard<std::mutex> lock{ g_mutex };
            ChangeConnectionInfo(connections[{ mgmt.addr2().to_string(),
                                               mgmt.addr1().to_string() }],
                                 tap,
                                 mgmt.rfind_pdu<Tins::Dot11AssocResponse>());
            break;
        }
        case Tins::Dot11::BEACON: {
            std::lock_guard<std::mutex> lock{ g_mutex };
            ChangeApInfo(aps[mgmt.addr2().to_string()],
                         tap,
                         mgmt.rfind_pdu<Tins::Dot11Beacon>());
            break;
        }
        default:
            return false;
        }
    }
    else {
        return false;
    }

    return true;
}

static void ReceiveInfo(const std::string interface,
                        std::map<std::string, ApInfo>& aps,
                        std::map<ConnectionInfoKey, ConnectionInfo>& connections,
                        std::atomic<bool>& stop) {
    using namespace std::literals::chrono_literals;

    Tins::Sniffer sniffer{ interface };
    while (!stop) {
        sniffer.sniff_loop([&aps, &connections](Tins::PDU& pdu) {
            try {
                return !UpdateInfo(aps,
                                   connections,
                                   pdu.rfind_pdu<Tins::RadioTap>());
            }
            catch (Tins::option_not_found&) {
                return true;
            }
        });
        std::this_thread::sleep_for(10ms);
    }
}

int Driver(const std::string interface) {
    std::map<std::string, ApInfo> aps;
    std::map<ConnectionInfoKey, ConnectionInfo> connections;

    std::atomic<bool> stop{ false };
    std::thread recive_thread{ ReceiveInfo,
                               interface,
                               std::ref(aps),
                               std::ref(connections),
                               std::ref(stop) };
    std::thread print_thread{ PrintInfo,
                              std::ref(aps),
                              std::ref(connections),
                              std::ref(stop) };

    std::string input;
    while(std::getline(std::cin, input));

    stop = true;
    recive_thread.join();
    print_thread.join();

    return 0;
}
