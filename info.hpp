#ifndef INFO_HPP
#define INFO_HPP

#include <string>
#include <utility>

#include <tins/radiotap.h>
#include <tins/dot11.h>

class ApInfo {
public:
    void Update(const Tins::Dot11Beacon& beacon,
                const Tins::RadioTap& tap);
    void Update(const Tins::Dot11Data& data,
                const Tins::RadioTap& tap);
    
    const auto bssid() const { return bssid_; }
    const auto power() const { return power_; }
    const auto beacons() const { return beacons_; }
    const auto data() const { return data_; }
    const auto per_second() const { return per_second_; }
    const auto channel() const { return channel_; }
    const auto mb() const { return mb_; }
    const auto enc() const { return enc_; }
    const auto cipher() const { return cipher_; }
    const auto auth() const { return auth_; }
    const auto essid() const { return essid_; }
private:
    std::string bssid_;
    int power_{ -1 };
    int beacons_{ 0 };
    int data_{ 0 };
    int per_second_{ 0 };
    int channel_;
    std::string mb_{ "-1" };
    std::string enc_;
    std::string cipher_;
    std::string auth_;
    std::string essid_;
    
    uint8_t mb_rate_;
    char mb_qos_{ 'e' };
    char mb_spa_{ ' ' };
};

class ConnectionInfo {
public:
    void Update(const Tins::Dot11ProbeRequest& probe_req,
                const Tins::RadioTap& tap);
    void Update(const Tins::Dot11ProbeResponse& probe_resp,
                const Tins::RadioTap& tap);
    void Update(const Tins::Dot11Data& data,
                const Tins::RadioTap& tap);

    const auto bssid() const { return bssid_; }
    const auto station() const { return station_; }
    const auto power() const { return power_; }
    const auto rate() const { return rate_; }
    const auto lost() const { return lost_; }
    const auto frames() const { return frames_; }
    const auto probe() const { return probe_; }
private:
    std::string bssid_;
    std::string station_;
    int power_{ -1 };
    std::string rate_;
    int lost_{ 0 };
    int frames_{ 0 };
    std::string probe_;
    
    std::pair<int, int> rate_num_{ 0, 0 };
    int seq_last_{ 0 };
    
    void UpdateRadioFromStation(const Tins::RadioTap& tap);
    void UpdateRadioFromAp(const Tins::RadioTap& tap);
    void UpdateRadioAfter(const Tins::RadioTap& tap);
    
    void ApplyAddress(const Tins::Dot11::address_type& bssid,
                       const Tins::Dot11::address_type& station);
};

#endif // INFO_HPP
