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
// #include <tins/rsn_information.h>

#include "driver.hpp"
#include "cli.hpp"
    
struct Dot11ApInfo {
    std::string bssid;
    std::string power;
    std::string beacons;
    std::string data; //
    std::string per_s; //
    std::string channel;
    std::string mb; //
    std::string enc; //
    std::string cipher; //
    std::string auth; //
    std::string essid;
};

struct Dot11StationInfoKey {
    std::string bssid;
    std::string station;
};

struct Dot11StationInfo {
    std::string bssid;
    std::string station;
    std::string power;
    std::string rate;
    std::string lost;
    std::string frames;
    std::string probe;
};

namespace {
std::mutex g_mutex;
}

void PrintInfo(const std::map<std::string, Dot11ApInfo>& ap_infos,
               const std::deque<Dot11StationInfo>& station_infos,
               std::atomic<bool>& stop) {
    using namespace std::chrono_literals;
    
    std::stringstream msg;
    const std::string ap_name{
        "\n"
        "  BSSID            "
        "  PWR"
        "  Beacons  "
        "  #Data, #/s"
        "  CH"
        "  MB  "
        "  ENC "
        "  CIPHER"
        "  AUTH"
        "  ESSID"
        "\n"
    };
                                    
    const std::string station_name{
        "\n"
        "  BSSID            "
        "  STATION          "
        "  PWR"
        "  Rate  "
        "  Lost"
        "  Frames"
        "  Probe"
        "\n"
    };
    
    cli::NextScreen();
    while (!stop) {
        msg << ap_name;
        std::this_thread::sleep_for(50ms);
        {
            std::lock_guard<std::mutex> lock{ g_mutex };
            for (const auto& p : ap_infos) {
                const auto& info = p.second;
                msg << std::left
                    << "  " << std::setw(17) << info.bssid
                    << std::right
                    << "  " << std::setw(3)  << info.power
                    << "  " << std::setw(7)  << info.beacons
                    << "  " << std::setw(7)  << info.data << std::setw(5) << info.per_s
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
        
        msg << station_name;
        std::this_thread::sleep_for(50ms);
        {
            std::lock_guard<std::mutex> lock{ g_mutex };
            for (const auto& info : station_infos) {
                msg << std::left
                    << "  " << std::setw(17) << info.bssid
                    << "  " << std::setw(17) << info.station
                    << std::right
                    << "  " << std::setw(3)  << info.power
                    << std::left
                    << "  " << std::setw(6)  << info.rate
                    << std::right
                    << "  " << std::setw(4)  << info.lost
                    << "  " << std::setw(6)  << info.frames
                    << std::internal
                    << "  " << info.probe << "\n";
            }
        }
        
        cli::Update(msg.str());
        msg.str(std::string{});
    }
}

//     change -> true
// not change -> false
bool UpdateInfo(std::map<std::string, Dot11ApInfo>& ap_infos,
                std::deque<Dot11StationInfo>& station_infos,
                const Tins::RadioTap& tap,
                const Tins::Dot11ManagementFrame& mgmt) {
    auto init_ap_info = [&](Dot11ApInfo& ap_info) {
        auto freq = tap.channel_freq();
        auto&& ssid = mgmt.ssid();
        
        ap_info.bssid = mgmt.addr2().to_string();
        ap_info.beacons = ap_info.beacons.empty() ?
                          std::to_string(1) : std::to_string(std::stoi(ap_info.beacons) + 1);
        ap_info.data;
        ap_info.per_s;
        ap_info.power = std::to_string(tap.dbm_signal());
        ap_info.channel = std::to_string(freq == 2484 ? 14 : freq % 2412 / 5 + 1);
        ap_info.mb;
        ap_info.enc;
        ap_info.cipher;
        ap_info.auth;
        
        ap_info.essid = ssid.empty() ? "<length:  0>" : ssid;
    };
    auto init_station_info = [&]() {
        Dot11StationInfo station_info;
        station_info.bssid = mgmt.addr2().to_string();
        station_info.station = mgmt.addr1().to_string();
        station_info.power = std::to_string(tap.dbm_signal());
        station_info.rate;
        station_info.lost;
        station_info.frames;
        station_info.probe;
        return station_info;
    };
    
    switch (mgmt.subtype()) {
    // case Tins::Dot11::ASSOC_REQ:
    case Tins::Dot11::ASSOC_RESP:
    // case Tins::Dot11::REASSOC_REQ:
    case Tins::Dot11::REASSOC_RESP:
    // case Tins::Dot11::PROBE_REQ:
    case Tins::Dot11::PROBE_RESP:
        try {
            std::lock_guard<std::mutex> lock{ g_mutex };
            if (station_infos.size() >= 10) {
                station_infos.pop_front();
            }
            station_infos.emplace_back(init_station_info());
        }
        catch (Tins::option_not_found&) {
            return false;
        }
        break;
    case Tins::Dot11::BEACON:
        try {
            std::lock_guard<std::mutex> lock{ g_mutex };
            init_ap_info(ap_infos[mgmt.addr2().to_string()]);
        }
        catch (Tins::option_not_found&) {
            return false;
        }
        break;
    // case Tins::Dot11::ATIM:
    // case Tins::Dot11::DISASSOC:
    // case Tins::Dot11::AUTH:
    // case Tins::Dot11::DEAUTH:
    default:
        break;
    }
    
    return true;
}

void ReceiveInfo(const std::string interface,
                 std::atomic<bool>& stop) {
    using namespace std::chrono_literals;
    
    std::map<std::string, Dot11ApInfo> ap_infos;
    std::deque<Dot11StationInfo> station_infos;
    
    std::thread print_thread{ PrintInfo,
                              std::ref(ap_infos),
                              std::ref(station_infos),
                              std::ref(stop) };
    
    Tins::Sniffer sniffer{ interface };
    while (!stop) {
        sniffer.sniff_loop([&ap_infos, &station_infos](Tins::PDU& pdu) {
            auto& tap = pdu.rfind_pdu<Tins::RadioTap>();
            return !UpdateInfo(ap_infos,
                               station_infos,
                               tap,
                               tap.rfind_pdu<Tins::Dot11ManagementFrame>());
        });
        std::this_thread::sleep_for(10ms);
    }
    
    print_thread.join();
}

int Driver(const std::string interface) {
    std::atomic<bool> stop{ false };
    std::thread recive_thread{ ReceiveInfo,
                               interface,
                               std::ref(stop) };
    
    std::string input;
    while(std::getline(std::cin, input));
    
    stop = true;
    recive_thread.join();
    
    return 0;
}
