#include <iostream>

#include "driver.hpp"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }
    return Driver(argv[1]);
}
