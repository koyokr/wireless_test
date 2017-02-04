#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <queue>
#include <algorithm>
#include <chrono>

#include <tins/packet_sender.h>
#include <tins/sniffer.h>
#include <tins/radiotap.h>
#include <tins/dot11.h>
#include <tins/tins.h>

#include "driver.hpp"
#include "cli.hpp"

namespace {
std::mutex g_mtx;
}

void RequestApInfo(const std::string interface, std::atomic<bool>& stop) {
    using namespace std::chrono_literals;
    
    Tins::Dot11Beacon probe;
    probe.addr1(Tins::Dot11::BROADCAST);
    probe.addr2("00:01:02:03:04:05");
    probe.addr3(probe.addr2());
    
    probe.ssid("ssid");
    probe.ds_parameter_set(8);
    probe.supported_rates({ 1.0f, 5.5f, 11.0f });
    //probe.rsn_information(Tins::RSNInformation::wpa2_psk());
    
    auto tap = Tins::RadioTap() / probe;
    Tins::PacketSender sender{ interface };
    
    while (!stop) {
        {
            std::lock_guard<std::mutex> lock{ g_mtx };
            sender.send(tap);
            std::this_thread::sleep_for(200ms);
        }
        std::this_thread::sleep_for(2000ms);
    }
}

struct Info {
    Tins::Dot11::address_type bssid;
    int8_t dbm_signal;
    std::string essid;
};

void UpdateScreen(std::map<Tins::Dot11::address_type, Info>& beacon_map,
                  std::deque<Info>& probe_deque) {
    // TODO: map to vector -> SLOW
    std::vector<Info> beacons;
    for (const auto& p : beacon_map) {
        beacons.emplace_back(p.second);
    }
    
    std::sort(beacons.begin(), beacons.end(), [](auto&& a, auto&& b) {
        return a.dbm_signal < b.dbm_signal;
    });
    
    std::string str;
    for (const auto& beacon : beacons) {
        str += ' ' + beacon.bssid.to_string();
        str += ' ' + std::to_string(beacon.dbm_signal);
        str += ' ' + beacon.essid;
        str += '\n';
    }
    
    cli::Update(str);
}

// change: true
// not change: false
bool UpdateApInfo(std::map<Tins::Dot11::address_type, Info>& beacon_map,
                  std::deque<Info>& probe_deque,
                  Tins::Dot11ManagementFrame& management,
                  int8_t dbm_signal) {
    constexpr int kProbeDequeMaxSize = 5;
    
    auto init_info = [&]() {
        return Info{ management.addr2(), dbm_signal, management.ssid() };
    };
    
    switch (management.subtype()) {
    case Tins::Dot11::PROBE_REQ:
    case Tins::Dot11::PROBE_RESP:
        if (probe_deque.size() >= kProbeDequeMaxSize) {
            probe_deque.pop_front();
        }
        probe_deque.emplace_back(init_info());
        //UpdateScreen(beacon_map, probe_deque);
        return true;
    case Tins::Dot11::BEACON:
        beacon_map[management.addr2()] = init_info();
        UpdateScreen(beacon_map, probe_deque);
        return true;
    default:
        return false;
    }
}

void ReceiveApInfo(const std::string interface, std::atomic<bool>& stop) {
    using namespace std::chrono_literals;
    
    std::map<Tins::Dot11::address_type, Info> beacon_map;
    std::deque<Info> probe_deque;
    
    Tins::SnifferConfiguration config;
    config.set_promisc_mode(true);
    Tins::Sniffer sniffer{ interface, config };
    
    cli::NextScreen();
    while (!stop) {
        std::lock_guard<std::mutex> lock{ g_mtx };
        sniffer.sniff_loop([&beacon_map, &probe_deque](Tins::PDU& pdu) {
            auto tap = pdu.rfind_pdu<Tins::RadioTap>();
            return !UpdateApInfo(beacon_map,
                                 probe_deque,
                                 tap.rfind_pdu<Tins::Dot11ManagementFrame>(),
                                 tap.dbm_signal());
        });
        std::this_thread::sleep_for(200ms);
    }
}

int Driver(const std::string interface) {
    std::atomic<bool> stop{ false };
    std::thread request_thread{ RequestApInfo, interface, std::ref(stop) };
    std::thread update_thread{ ReceiveApInfo, interface, std::ref(stop) };
    
    std::string str;
    while(std::getline(std::cin, str));
    
    stop = true;
    request_thread.join();
    update_thread.join();
    
    return 0;
}
