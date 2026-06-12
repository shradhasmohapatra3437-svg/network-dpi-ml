#include "exporter.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

void Exporter::exportToJS(const std::vector<CaptureService::Packet>& packets, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Cannot open file " << filename << std::endl;
        return;
    }

    file << "var packets = [\n";

    for (size_t i = 0; i < packets.size(); ++i) {
        const auto& p = packets[i];

        // Build hex string of first 16 bytes
        std::ostringstream hex;
        for (size_t j = 0; j < std::min((size_t)16, p.data.size()); ++j) {
            hex << std::hex << std::setw(2) << std::setfill('0') << (int)p.data[j];
            if (j < 15) hex << " ";
        }

        file << "  {\n";
        file << "    timestamp: " << p.timestamp << ",\n";
        file << "    length: " << p.length << ",\n";
        file << "    data: \"" << hex.str() << "\"\n";
        file << "  }";
        if (i < packets.size() - 1) file << ",";
        file << "\n";
    }

    file << "];\n";
    file.close();
    std::cout << "[INFO] Exported " << packets.size() << " packets to " << filename << "\n";
}

