#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include "capture_engine.h"
#include "packet_parser.h"

using namespace CaptureService;
using namespace std;

// -------------------- JSON helpers --------------------
string escapeJson(const string& s) {
    string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

// -------------------- Per-packet result struct --------------------
struct PacketResult {
    int         id;
    string      src_ip;
    string      dst_ip;
    string      protocol;
    int         src_port;
    int         dst_port;
    string      ml;
    string      decision;
    string      app;
    long long   timestamp;
    int         length;
};

vector<PacketResult> packetLog;

// -------------------- Write JSON --------------------
void writeJSON(const string& filename) {
    ofstream f(filename);
    if (!f.is_open()) return;

    f << "{\n";
    f << "  \"stats\": {\n";
    f << "    \"total\": "   << totalPackets   << ",\n";
    f << "    \"tcp\": "     << tcpPackets     << ",\n";
    f << "    \"udp\": "     << udpPackets     << ",\n";
    f << "    \"allowed\": " << allowedPackets << ",\n";
    f << "    \"blocked\": " << blockedPackets << "\n";
    f << "  },\n";
    f << "  \"packets\": [\n";

    for (size_t i = 0; i < packetLog.size(); i++) {
        const auto& p = packetLog[i];
        f << "    {\n";
        f << "      \"id\": "         << p.id                       << ",\n";
        f << "      \"src_ip\": \""   << escapeJson(p.src_ip)       << "\",\n";
        f << "      \"dst_ip\": \""   << escapeJson(p.dst_ip)       << "\",\n";
        f << "      \"protocol\": \"" << escapeJson(p.protocol)     << "\",\n";
        f << "      \"src_port\": "   << p.src_port                 << ",\n";
        f << "      \"dst_port\": "   << p.dst_port                 << ",\n";
        f << "      \"ml\": \""       << escapeJson(p.ml)           << "\",\n";
        f << "      \"decision\": \"" << escapeJson(p.decision)     << "\",\n";
        f << "      \"app\": \""      << escapeJson(p.app)          << "\",\n";
        f << "      \"timestamp\": "  << p.timestamp                << ",\n";
        f << "      \"length\": "     << p.length                   << "\n";
        f << "    }";
        if (i < packetLog.size() - 1) f << ",";
        f << "\n";
    }

    f << "  ]\n}\n";
    f.close();
}

// -------------------- IPv4 Helper --------------------
string ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    char* s = inet_ntoa(addr);
    if (s) return string(s);
    return "0.0.0.0";
}

// -------------------- Run DPI Analysis --------------------
void runAnalysis() {
    CaptureService::totalPackets   = 0;
    CaptureService::allowedPackets = 0;
    CaptureService::blockedPackets = 0;
    CaptureService::tcpPackets     = 0;
    CaptureService::udpPackets     = 0;
    packetLog.clear();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed\n";
        return;
    }

    cout << "[INFO] Winsock initialized successfully.\n";

    string filename = "data/test.pcap";
    CaptureEngine engine;

    if (!engine.init(filename)) {
        cerr << "[ERROR] Failed to initialize CaptureEngine\n";
        WSACleanup();
        return;
    }

    cout << "[INFO] PCAP file opened: " << filename << "\n";
    cout << "\nReading Packets...\n\n";

    Packet pkt;
    int count = 0;

    while (engine.getNextPacket(pkt)) {
        count++;

        cout << "Packet #" << count << "\n";
        cout << "Timestamp: " << pkt.timestamp << "\n";
        cout << "Length: " << pkt.length << " bytes\n";

        cout << "Data (first 16 bytes): ";
        for (size_t i = 0; i < min((size_t)16, pkt.data.size()); i++) {
            cout << hex << setw(2) << setfill('0') << (int)pkt.data[i] << " ";
        }
        cout << dec << "\n";
        cout << "-----------------------------\n";

        // Save pre-parse stats snapshot to detect what changed
        int prevAllowed = allowedPackets;
        int prevBlocked = blockedPackets;
        int prevTcp     = tcpPackets;
        int prevUdp     = udpPackets;

        PacketParser::parse(pkt);

        // Build result record from what the parser updated
        PacketResult r;
        r.id        = count;
        r.timestamp = pkt.timestamp;
        r.length    = pkt.length;
        r.ml        = "NORMAL";
        r.decision  = (blockedPackets > prevBlocked) ? "BLOCKED" : "ALLOWED";
        r.app       = "";

        // Determine protocol
        if (tcpPackets > prevTcp) {
            r.protocol = "TCP";
            r.src_port = 0;
            r.dst_port = 0;
        } else if (udpPackets > prevUdp) {
            r.protocol = "UDP";
            r.src_port = 0;
            r.dst_port = 0;
        } else {
            r.protocol = "OTHER";
            r.src_port = 0;
            r.dst_port = 0;
        }

        // Extract IPs from raw packet data
        if (pkt.data.size() >= 34) {
            const uint8_t* data = pkt.data.data();
            uint32_t src_ip, dst_ip;
            memcpy(&src_ip, data + 26, 4);
            memcpy(&dst_ip, data + 30, 4);

            char buf[INET_ADDRSTRLEN];
            struct in_addr addr;

            addr.s_addr = src_ip;
            r.src_ip = string(inet_ntoa(addr));

            addr.s_addr = dst_ip;
            r.dst_ip = string(inet_ntoa(addr));

            // Extract ports for TCP/UDP
            if (r.protocol == "TCP" && pkt.data.size() >= 38) {
                int ihl = (data[14] & 0x0F) * 4;
                r.src_port = (data[14 + ihl] << 8) | data[14 + ihl + 1];
                r.dst_port = (data[14 + ihl + 2] << 8) | data[14 + ihl + 3];
                if (r.dst_port == 443 || r.src_port == 443) r.app = "HTTPS";
                else if (r.dst_port == 80 || r.src_port == 80) r.app = "HTTP";
            } else if (r.protocol == "UDP" && pkt.data.size() >= 38) {
                int ihl = (data[14] & 0x0F) * 4;
                r.src_port = (data[14 + ihl] << 8) | data[14 + ihl + 1];
                r.dst_port = (data[14 + ihl + 2] << 8) | data[14 + ihl + 3];
                if (r.dst_port == 53 || r.src_port == 53) r.app = "DNS";
            }
        }

        packetLog.push_back(r);

        // Write JSON after every packet so dashboard updates live
        writeJSON("data/packets.json");
    }

    cout << "\nTotal Packets Read: " << count << "\n";
    cout << "Analysis complete. You can now view statistics.\n";
    cout << "[INFO] Dashboard data saved to data/packets.json\n";
    cout << "[INFO] Open dashboard.html in your browser to view results.\n";

    engine.close();
    WSACleanup();
}

// -------------------- Show Statistics --------------------
void showStats() {
    if (totalPackets == 0) {
        cout << "\nNo data available. Run analysis first.\n";
        return;
    }
    printStats();
}

// -------------------- MAIN MENU --------------------
int main() {
    int choice;

    do {
        cout << "\n===== DPI SYSTEM MENU =====\n";
        cout << "1. Load PCAP and Analyze\n";
        cout << "2. View Statistics\n";
        cout << "3. Exit\n";
        cout << "Enter choice: ";
        cin >> choice;

        switch (choice) {
        case 1: runAnalysis(); break;
        case 2: showStats();   break;
        case 3: cout << "Exiting...\n"; break;
        default: cout << "Invalid choice\n";
        }

    } while (choice != 3);

    return 0;
}
