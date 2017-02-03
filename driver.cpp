#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <map>
#include <queue>
#include <chrono>

#include <tins/dot11.h>

#include "driver.hpp"
#include "cli.hpp"
#include "dot11sniff.hpp"

void RequestApInfo(const std::string interface, std::atomic<bool>& stop) {
    using namespace std::chrono_literals;
    while (!stop) {
        // TODO: request frame
        std::this_thread::sleep_for(1s);
    }
}

void UpdateApInfo(const std::string interface, std::atomic<bool>& stop) {
    std::map<Tins::Dot11::address_type, int> ap_map; // TODO int -> ap_info
    std::queue<int> log_queue; // TODO: int -> log_queue
    
    Dot11Sniffer sniffer{ interface };
    while (!stop) {
        auto dot11 = sniffer.NextDot11();
        ap_map[dot11.addr1()] = 0; // TODO: 0 -> get_ap_info()
    }
}

int Driver(const std::string interface) {
    cli::NextScreen();
    
    std::atomic<bool> stop{ false };
    std::thread request_thread{ RequestApInfo, interface, std::ref(stop) };
    std::thread update_thread{ UpdateApInfo, interface, std::ref(stop) };
    
    std::string str;
    while(std::getline(std::cin, str));
    
    stop = true;
    request_thread.join();
    update_thread.join();
    
    return 0;
}
