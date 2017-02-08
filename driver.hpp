#ifndef DRIVER_HPP
#define DRIVER_HPP

#include <string>

struct ApInfo {
    std::string bssid;
    std::string power;
    std::string beacons{ "0" };
    std::string data{ "0" };
    std::string per_second{ "0" };
    std::string channel;
    std::string mb{ "-1" };
    std::string enc;
    std::string cipher;
    std::string auth;
    std::string essid;
};

struct ConnectionInfo {
    std::string bssid{ "(not associated)" };
    std::string station;
    std::string power;
    std::string rate{ "0-0" };
    std::string lost{ "0" };
    std::string frames{ "0" };
    std::string probe;
};

using ConnectionInfoKey = std::pair<std::string, std::string>;

int Driver(const std::string interface);

#endif // DRIVER_HPP
