#include <iostream>
#include <string>
#include <vector>

#include "cli.hpp"

namespace cli {

namespace {
void ClearCurEnd() { std::cout << "\E[0J"; }
void ClearCurBeg() { std::cout << "\E[1J"; }
void ClearBegEnd() { std::cout << "\E[2J"; }
void MoveCurBeg() { std::cout << "\E[f"; }

void Clear() { ClearCurBeg(); MoveCurBeg(); }
}

void NextScreen() {
    ClearBegEnd();
    MoveCurBeg();
    std::cout << std::flush;
}

void Update(const std::string& msg) {
    Clear();
    std::cout << msg << std::flush;
}
void Update(const std::vector<std::string>& msgs) {
    Clear();
    for (const auto& msg : msgs) {
        std::cout << msg << '\n';
    }
    std::cout << std::flush;
}
} // namespace cli
