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
    
struct Dot11Info {
    std::string bssid;
    std::string power;
    std::string beacons;
    // std::string data;
    // std::string per_s;
    std::string channel;
    // std::string MB;
    // std::string ENC;
    // std::string CIPHER;
    // std::string AUTH;
    std::string essid;
};

namespace {
    std::mutex g_mutex;
}

void PrintInfo(const std::map<std::string, Dot11Info>& info_map,
               const std::deque<Dot11Info>& info_deque,
               const std::atomic<bool>& stop) {
    using namespace std::chrono_literals;
    
    std::stringstream msg;
    const std::string str{ "  BSSID            "
                           "  PWR"
                           "  Beacons"
                           "  CH"
                           "  ESSID\n" };
    
    while (!stop) {
        msg.str(std::string());
        msg << str;
        
        std::this_thread::sleep_for(200ms);
        {
            std::lock_guard<std::mutex> lock{ g_mutex };
            for (const auto& p : info_map) {
                const auto& info = p.second;
                msg << std::setw(2 + 17) << info.bssid
                    << std::setw(2 + 3)  << info.power
                    << std::setw(2 + 7)  << info.beacons
                    << std::setw(2 + 2)  << info.channel
                    << "  " << info.essid << "\n";
            }
        }
        cli::Update(msg.str());
    }
}

// change -> true
// not change -> false
bool UpdateInfo(std::map<std::string, Dot11Info>& info_map,
                std::deque<Dot11Info>& info_deque,
                const Tins::RadioTap& tap,
                const Tins::Dot11ManagementFrame& mgmt) {
    auto init_info = [&](Dot11Info& info) {
        auto freq = tap.channel_freq();
        auto&& ssid = mgmt.ssid();
        
        std::lock_guard<std::mutex> lock{ g_mutex };
        info.bssid = mgmt.addr2().to_string();
        info.beacons = info.beacons.empty() ?
                       std::to_string(1) : std::to_string(std::stoi(info.beacons) + 1);
        info.power = std::to_string(tap.dbm_signal());
        info.channel = std::to_string(freq == 2484 ? 14 : freq % 2412 / 5 + 1);
        info.essid = ssid.empty() ? "<length:  0>" : ssid;
    };
    
    switch (mgmt.subtype()) {
    case Tins::Dot11::PROBE_REQ:
    case Tins::Dot11::PROBE_RESP:
        break;
    case Tins::Dot11::BEACON:
        try {
            init_info(info_map[mgmt.addr2().to_string()]);
        }
        catch (Tins::option_not_found&) {
            return false;
        }
        break;
    default:
        break;
    }
    
    return true;
}

void ReceiveInfo(const std::string interface,
                 const std::atomic<bool>& stop) {
    using namespace std::chrono_literals;
    std::map<std::string, Dot11Info> info_map;
    std::deque<Dot11Info> info_deque;
    
    Tins::SnifferConfiguration config;
    config.set_promisc_mode(true);
    Tins::Sniffer sniffer{ interface, config };
    
    cli::NextScreen();
    std::thread print_thread{ PrintInfo,
                              std::ref(info_map),
                              std::ref(info_deque),
                              std::ref(stop) };
    
    while (!stop) {
        sniffer.sniff_loop([&info_map, &info_deque](Tins::PDU& pdu) {
            auto tap = pdu.rfind_pdu<Tins::RadioTap>();
            return !UpdateInfo(info_map,
                               info_deque,
                               tap,
                               tap.rfind_pdu<Tins::Dot11ManagementFrame>());
        }, 10'000);
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
