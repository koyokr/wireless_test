#include <iostream>
#include <string>
#include <vector>

#include "cli.hpp"

namespace cli {
static void ClearCurEnd() { std::cout << "\E[0J"; }
static void ClearCurBeg() { std::cout << "\E[1J"; }
static void ClearBegEnd() { std::cout << "\E[2J"; }
static void MoveCurBeg() { std::cout << "\E[f"; }

void NextScreen() {
    ClearBegEnd();
    MoveCurBeg();
    std::cout << std::flush;
}

static void Clear() { ClearCurBeg(); MoveCurBeg(); }

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
