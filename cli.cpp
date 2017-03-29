#include <iostream>
#include <string>
#include <vector>

#include "cli.hpp"

namespace cli {
static std::string ClearCurEnd() { return "\E[0J"; }
static std::string ClearCurBeg() { return "\E[1J"; }
static std::string ClearBegEnd() { return "\E[2J"; }
static std::string  MoveCurBeg() { return "\E[f";  }

void NextScreen() {
    std::cout << ClearBegEnd()
              << MoveCurBeg()
              << std::flush;
}

static std::string Clear() {
    return ClearCurBeg() + MoveCurBeg();
}

void Update(std::string const& msg) {
    std::cout << Clear()
              << msg
              << std::flush;
}
void Update(std::vector<std::string> const& msgs) {
    std::cout << Clear();
    for (auto const& msg : msgs) {
        std::cout << msg << '\n';
    }
    std::cout << std::flush;
}
} // namespace cli
