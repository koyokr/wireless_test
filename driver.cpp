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

#include "driver.hpp"
#include "info.hpp"
#include "cli.hpp"

namespace {
std::mutex g_mutex;
}

static void PrintInfo(const std::map<std::string, ApInfo>& aps,
                      const std::map<std::string, ConnectionInfo>& connections,
                      std::atomic<bool>& stop) {
    using namespace std::literals::chrono_literals;

    std::stringstream msg;
    const std::string ap_row{
        "\n"
        // left
        "  BSSID            "
        // right
        "  PWR"
        "  Beacons  "
        "  #Data,"
        "  #/s"
        "  CH"
        // left
        "  MB  "
        "  ENC   "
        "  CIPHER"
        "  AUTH"
        "  ESSID"
        "\n"
    };
    const std::string connection_row{
        "\n"
        // left
        "  BSSID            "
        "  STATION          "
        // right
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
        std::this_thread::sleep_for(5ms);
        {
            std::lock_guard<std::mutex> lock{ g_mutex };
            for (const auto& p : aps) {
                const auto& ap = p.second;
                msg << std::left
                    << "  " << std::setw(17) << ap.bssid()
                    << std::right
                    << "  " << std::setw(3)  << ap.power()
                    << "  " << std::setw(7)  << ap.beacons()
                    << "  " << std::setw(7)  << ap.data()
                    << "  " << std::setw(4)  << ap.per_second()
                    << "  " << std::setw(2)  << ap.channel()
                    << std::left
                    << "  " << std::setw(4)  << ap.mb()
                    << "  " << std::setw(6)  << ap.enc()
                    << "  " << std::setw(6)  << ap.cipher()
                    << "  " << std::setw(4)  << ap.auth()
                    << "  " << ap.essid() << "\n";
            }
        }

        msg << connection_row;
        std::this_thread::sleep_for(5ms);
        {
            std::lock_guard<std::mutex> lock{ g_mutex };
            for (const auto& p : connections) {
                const auto& connection = p.second;
                msg << std::left
                    << "  " << std::setw(17) << connection.bssid()
                    << "  " << std::setw(17) << connection.station()
                    << std::right
                    << "  " << std::setw(3)  << connection.power()
                    << "  " << std::setw(7)  << connection.rate()
                    << "  " << std::setw(4)  << connection.lost()
                    << "  " << std::setw(6)  << connection.frames()
                    << "  " << connection.probe() << "\n";
            }
        }

        msg << "\n";
        cli::Update(msg.str());
        msg.str(std::string{});
    }
}

//     update data -> true
// not update data -> false
static bool UpdateInfo(std::map<std::string, ApInfo>& aps,
                       std::map<std::string, ConnectionInfo>& connections,
                       const Tins::RadioTap& tap) {
    decltype(auto) dot11 = tap.rfind_pdu<Tins::Dot11>();
    const auto type = dot11.type();

    if (Tins::Dot11::DATA == type) {
        decltype(auto) data = dot11.rfind_pdu<Tins::Dot11Data>();
        const auto bssid = data.addr1().to_string(); // destination
        const auto station = data.addr2().to_string(); // source
        
        if (aps.find(bssid) == aps.end()) {
            return false;
        }
        std::lock_guard<std::mutex> lock{ g_mutex };
        aps[bssid].Update(data, tap);
        connections[station].Update(data, tap);
    }
    else if (Tins::Dot11::MANAGEMENT == type) {
        const auto subtype = dot11.subtype();
        
        if (Tins::Dot11::PROBE_REQ == subtype) {
            decltype(auto) probe_req = dot11.rfind_pdu<Tins::Dot11ProbeRequest>();
            const std::string station = probe_req.addr2().to_string(); // destination
            
            std::lock_guard<std::mutex> lock{ g_mutex };
            connections[station].Update(probe_req, tap);
        }
        else if (Tins::Dot11::PROBE_RESP == subtype) {
            decltype(auto) probe_resp = dot11.rfind_pdu<Tins::Dot11ProbeResponse>();
            const std::string station = probe_resp.addr1().to_string(); // source
            
            if (connections.find(station) == connections.end()) {
                return false;
            }
            std::lock_guard<std::mutex> lock{ g_mutex };
            connections[station].Update(probe_resp, tap);
        }
        else if (Tins::Dot11::BEACON == subtype) {
            decltype(auto) beacon = dot11.rfind_pdu<Tins::Dot11Beacon>();
            const auto bssid = beacon.addr2().to_string(); // source
            
            std::lock_guard<std::mutex> lock{ g_mutex };
            aps[bssid].Update(beacon, tap);
        }
    }
    else { // Tins::Dot11::CONTROL == type
        return false;
    }

    return true;
}

static void ReceiveInfo(const std::string interface,
                        std::map<std::string, ApInfo>& aps,
                        std::map<std::string, ConnectionInfo>& connections,
                        std::atomic<bool>& stop) {
    Tins::Sniffer sniffer{ interface };
    
    while (!stop) {
        sniffer.sniff_loop([&aps, &connections](Tins::PDU& pdu) {
            return !UpdateInfo(aps,
                                connections,
                                pdu.rfind_pdu<Tins::RadioTap>());
        });
    }
}

int Driver(const std::string interface) {
    std::map<std::string, ApInfo> aps;
    std::map<std::string, ConnectionInfo> connections;

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
