#ifndef CLI_HPP
#define CLI_HPP

#include <string>
#include <vector>

namespace cli {
void NextScreen();
void Update(std::string const& msg);
void Update(std::vector<std::string> const& msgs);
} // namespace cli

#endif // CLI_HPP
