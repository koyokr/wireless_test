#ifndef CLI_HPP
#define CLI_HPP

#include <string>
#include <vector>

namespace cli {
void NextScreen();
void Update(const std::string& msg);
void Update(const std::vector<std::string>& msgs);
} // namespace cli

#endif // CLI_HPP
