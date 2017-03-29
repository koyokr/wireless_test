#ifndef INFO_HPP
#define INFO_HPP

#include <string>
#include <utility>

#include <tins/radiotap.h>
#include <tins/dot11.h>

class ApInfo {
public:
    void Update(Tins::Dot11Beacon const& beacon,
                Tins::RadioTap const& tap);
    void Update(Tins::Dot11Data const& data,
                Tins::RadioTap const& tap);
    
    auto const bssid() const { return bssid_; }
    auto const power() const { return power_; }
    auto const beacons() const { return beacons_; }
    auto const data() const { return data_; }
    auto const per_second() const { return per_second_; }
    auto const channel() const { return channel_; }
    auto const mb() const { return mb_; }
    auto const enc() const { return enc_; }
    auto const cipher() const { return cipher_; }
    auto const auth() const { return auth_; }
    auto const essid() const { return essid_; }
private:
    std::string bssid_;
    int power_{ -1 };
    int beacons_{ 0 };
    int data_{ 0 };
    int per_second_{ 0 };
    int channel_{ -1 };
    std::string mb_{ "-1" };
    std::string enc_;
    std::string cipher_;
    std::string auth_;
    std::string essid_;
    
    int data_latest_{ 0 };
};

class ConnectionInfo {
public:
    void Update(Tins::Dot11ProbeRequest const& probe_req,
                Tins::RadioTap const& tap);
    void Update(Tins::Dot11ProbeResponse const& probe_resp,
                Tins::RadioTap const& tap);
    void Update(Tins::Dot11Data const& data,
                Tins::RadioTap const& tap);

    auto const bssid() const { return bssid_; }
    auto const station() const { return station_; }
    auto const power() const { return power_; }
    auto const rate() const { return rate_; }
    auto const lost() const { return lost_; }
    auto const frames() const { return frames_; }
    auto const probe() const { return probe_; }
private:
    std::string bssid_;
    std::string station_;
    int power_{ -1 };
    std::string rate_;
    int lost_{ 0 };
    int frames_{ 0 };
    std::string probe_;
    
    std::pair<int, int> rate_number_{ 0, 0 };
    int seq_last_{ 0 };
    
    void UpdateRateFromStation(Tins::RadioTap const& tap);
    void UpdateRateFromAp(Tins::RadioTap const& tap);
    void UpdateRateString();
    
    void ApplyAddress(Tins::Dot11::address_type const& bssid,
                      Tins::Dot11::address_type const& station);
};

#endif // INFO_HPP
