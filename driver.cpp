#include "driver.hpp"
#include "info.hpp"
#include "cli.hpp"

#include <tins/sniffer.h>
#include <tins/radiotap.h>
#include <tins/dot11.h>

#include <sstream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <map>
#include <queue>
#include <chrono>

using namespace std;

namespace {
mutex g_mutex;
}

static void PrintInfo(map<string, ApInfo> const& aps,
                      map<string, ConnectionInfo> const& connections,
                      atomic<bool> const& stop) {
    using namespace literals::chrono_literals;

    stringstream msg;
    string const ap_row{
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
    string const connection_row{
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
        this_thread::sleep_for(5ms);
        {
            lock_guard<mutex> lock{ g_mutex };
            for (auto const& p : aps) {
                auto const& ap = p.second;
                msg << left
                    << "  " << setw(17) << ap.bssid()
                    << right
                    << "  " << setw(3)  << ap.power()
                    << "  " << setw(7)  << ap.beacons()
                    << "  " << setw(7)  << ap.data()
                    << "  " << setw(4)  << ap.per_second()
                    << "  " << setw(2)  << ap.channel()
                    << left
                    << "  " << setw(4)  << ap.mb()
                    << "  " << setw(6)  << ap.enc()
                    << "  " << setw(6)  << ap.cipher()
                    << "  " << setw(4)  << ap.auth()
                    << "  " << ap.essid() << "\n";
            }
        }

        msg << connection_row;
        this_thread::sleep_for(5ms);
        {
            lock_guard<mutex> lock{ g_mutex };
            for (auto const& p : connections) {
                auto const& connection = p.second;
                msg << left
                    << "  " << setw(17) << connection.bssid()
                    << "  " << setw(17) << connection.station()
                    << right
                    << "  " << setw(3)  << connection.power()
                    << "  " << setw(7)  << connection.rate()
                    << "  " << setw(4)  << connection.lost()
                    << "  " << setw(6)  << connection.frames()
                    << "  " << connection.probe() << "\n";
            }
        }

        msg << "\n";
        cli::Update(msg.str());
        msg.str(string{});
    }
}

//     update data -> true
// not update data -> false
static bool UpdateInfo(map<string, ApInfo>& aps,
                       map<string, ConnectionInfo>& connections,
                       Tins::RadioTap const& tap) {
    auto const& dot11 = tap.rfind_pdu<Tins::Dot11>();
    auto const type = dot11.type();

    if (Tins::Dot11::DATA == type) {
        auto const& data = dot11.rfind_pdu<Tins::Dot11Data>();
        auto const bssid = data.addr1().to_string(); // destination
        auto const station = data.addr2().to_string(); // source

        if (aps.find(bssid) == aps.end())
            return false;

        lock_guard<mutex> lock{ g_mutex };
        aps[bssid].Update(data, tap);
        connections[station].Update(data, tap);
    }
    else if (Tins::Dot11::MANAGEMENT == type) {
        auto const subtype = dot11.subtype();
        
        if (Tins::Dot11::PROBE_REQ == subtype) {
            auto const& probe_req = dot11.rfind_pdu<Tins::Dot11ProbeRequest>();
            string const station = probe_req.addr2().to_string(); // destination
            
            lock_guard<mutex> lock{ g_mutex };
            connections[station].Update(probe_req, tap);
        }
        else if (Tins::Dot11::PROBE_RESP == subtype) {
            auto const& probe_resp = dot11.rfind_pdu<Tins::Dot11ProbeResponse>();
            string const station = probe_resp.addr1().to_string(); // source
            
            if (connections.find(station) == connections.end())
                return false;

            lock_guard<mutex> lock{ g_mutex };
            connections[station].Update(probe_resp, tap);
        }
        else if (Tins::Dot11::BEACON == subtype) {
            auto const& beacon = dot11.rfind_pdu<Tins::Dot11Beacon>();
            auto const bssid = beacon.addr2().to_string(); // source
            
            lock_guard<mutex> lock{ g_mutex };
            aps[bssid].Update(beacon, tap);
        }
    }
    else { // Tins::Dot11::CONTROL == type
        return false;
    }

    return true;
}

static void ReceiveInfo(string const interface,
                        map<string, ApInfo>& aps,
                        map<string, ConnectionInfo>& connections,
                        atomic<bool>& stop) {
    Tins::Sniffer sniffer{ interface };
    
    while (!stop) {
        sniffer.sniff_loop([&aps, &connections](Tins::PDU& pdu) {
            return !UpdateInfo(aps,
                               connections,
                               pdu.rfind_pdu<Tins::RadioTap>());
        });
    }
}

int Driver(string const interface) {
    map<string, ApInfo> aps;
    map<string, ConnectionInfo> connections;

    atomic<bool> stop{ false };
    thread recive_thread{ ReceiveInfo,
                               interface,
                               ref(aps),
                               ref(connections),
                               ref(stop) };
    thread print_thread{ PrintInfo,
                              ref(aps),
                              ref(connections),
                              ref(stop) };

    string input;
    while(getline(cin, input));

    stop = true;
    recive_thread.join();
    print_thread.join();

    return 0;
}
