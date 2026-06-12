#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include "pcap_reader.h"
#include "packet.h"

namespace CaptureService
{

    // ================= ETHERNET HEADER =================
    struct EthernetHeader
    {
        uint8_t dest[6];
        uint8_t src[6];
        uint16_t type;
    };

    // ================= IPv4 HEADER =================
    struct IPv4Header
    {
        uint8_t version_ihl;
        uint8_t tos;
        uint16_t total_length;
        uint16_t id;
        uint16_t flags_fragment;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        uint32_t src_ip;
        uint32_t dst_ip;
    };

    // ================= TCP HEADER =================
    struct TCPHeader
    {
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t seq;             // Added: Required for correct struct size
        uint32_t ack;             // Added: Required for correct struct size
        uint8_t  data_offset_res; // Added: REQUIRED for your parsing logic
        uint8_t  flags;           // Added: Required for correct struct size
        uint16_t window;          // Added: Required for correct struct size
        uint16_t checksum;        // Added: Required for correct struct size
        uint16_t urgent_ptr;      // Added: Required for correct struct size
    };

    // ================= UDP HEADER =================
    struct UDPHeader
    {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;          // Added: Standard UDP field
        uint16_t checksum;        // Added: Standard UDP field
    };

    // ================= PACKET PARSER CLASS =================
    class PacketParser
    {
    public:
        static bool parse(const Packet &pkt);

    private:
        // blocked sites list
        static std::vector<std::string> blocked_sites;

        // helper functions
        static bool isBlocked(const std::string& domain);
        static std::string extractDNSQuery(const uint8_t* payload, int payload_len);
    };

    // ================= STATISTICS =================
    extern int totalPackets;
    extern int blockedPackets;
    extern int allowedPackets;
    extern int tcpPackets;
    extern int udpPackets;

    // ================= ML FUNCTION (ADDED) =================
    std::string callMLAPI(std::string proto, int sport, int dport, int sbytes, int dbytes);

    // ================= STATISTICS FUNCTION =================
    void printStats();

} // namespace CaptureService

#endif // PACKET_PARSER_H





