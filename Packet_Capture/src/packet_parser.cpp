#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0600

#include <winsock2.h> 
#include <ws2tcpip.h>

#include <cstdio>    
#include <cstdlib>   
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

// We manually declare the functions for the compiler.
extern "C" {
    FILE* _popen(const char* command, const char* mode);
    int _pclose(FILE* stream);
}

#ifdef _WIN32
  #define popen _popen
  #define pclose _pclose
#endif

#include "packet_parser.h"

using namespace std;

namespace CaptureService
{

// ================= GLOBAL STATS =================
int totalPackets = 0;
int blockedPackets = 0;
int allowedPackets = 0;

int tcpPackets = 0;
int udpPackets = 0;

// ================= BLOCK LIST =================
vector<string> PacketParser::blocked_sites = {
    "facebook.com",
    "instagram.com",
    "youtube.com",
    "twitter.com"
};

// ================= BLOCK CHECK =================
bool PacketParser::isBlocked(const string &domain)
{
    for (const auto &site : blocked_sites)
    {
        if (domain.find(site) != string::npos)
            return true;
    }
    return false;
}

// ================= ML API CALL =================
string callMLAPI(string proto, int sport, int dport, int sbytes, int dbytes)
{
    string cmd =
        "curl -s -X POST http://127.0.0.1:5000/predict "
        "-H \"Content-Type: application/json\" "
        "-d \"{\\\"proto\\\":\\\"" + proto +
        "\\\",\\\"sport\\\":" + to_string(sport) +
        ",\\\"dport\\\":" + to_string(dport) +
        ",\\\"sbytes\\\":" + to_string(sbytes) +
        ",\\\"dbytes\\\":" + to_string(dbytes) + "}\"";

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "NORMAL";

    char buffer[128];
    string result = "";

    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        result += buffer;
    }

    pclose(pipe);

    if (result.find("ATTACK") != string::npos)
        return "ATTACK";

    return "NORMAL";
}

// ================= DNS EXTRACT =================
string PacketParser::extractDNSQuery(const uint8_t* payload, int len)
{
    if (len < 12) return "";

    int pos = 12;
    string domain;

    int jump_pos = -1;
    bool jumped = false;

    while (pos < len)
    {
        uint8_t length = payload[pos];

        if (length == 0)
        {
            if (!jumped) pos++;
            break;
        }

        if ((length & 0xC0) == 0xC0)
        {
            if (pos + 1 >= len) return "";

            int pointer = ((length & 0x3F) << 8) | payload[pos + 1];

            if (pointer >= len) return "";

            if (!jumped)
            {
                jump_pos = pos + 2;
            }

            pos = pointer;
            jumped = true;
            continue;
        }

        if (length > 63 || pos + length >= len)
            return "";

        pos++;

        for (int i = 0; i < length && pos < len; i++)
        {
            domain += (char)payload[pos++];
        }

        domain += '.';
    }

    if (!domain.empty())
        domain.pop_back();

    return domain;
}

// ================= PRINT STATS =================
void printStats()
{
    cout << "\n===== DPI STATISTICS =====\n";
    cout << "Total Packets: " << totalPackets << endl;
    cout << "TCP Packets:   " << tcpPackets << endl;
    cout << "UDP Packets:   " << udpPackets << endl;
    cout << "Allowed:       " << allowedPackets << endl;
    cout << "Blocked:       " << blockedPackets << endl;
}

// ================= PARSER =================
bool PacketParser::parse(const Packet &pkt)
{
    totalPackets++;

    if (pkt.data.size() < 34)
        return true;

    const uint8_t *data = pkt.data.data();

    EthernetHeader *eth = (EthernetHeader *)data;
    uint16_t eth_type = ntohs(eth->type);

    if (eth_type != 0x0800)
        return true;

    IPv4Header *ip = (IPv4Header *)(data + 14);
    int ip_header_len = (ip->version_ihl & 0x0F) * 4;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    sprintf(src_ip, "%d.%d.%d.%d",
            ip->src_ip & 0xFF,
            (ip->src_ip >> 8) & 0xFF,
            (ip->src_ip >> 16) & 0xFF,
            (ip->src_ip >> 24) & 0xFF);

    sprintf(dst_ip, "%d.%d.%d.%d",
            ip->dst_ip & 0xFF,
            (ip->dst_ip >> 8) & 0xFF,
            (ip->dst_ip >> 16) & 0xFF,
            (ip->dst_ip >> 24) & 0xFF);

    cout << " | Src IP: " << src_ip << endl;
    cout << " | Dst IP: " << dst_ip << endl;

    // ================= TCP =================
    if (ip->protocol == 6)
    {
        tcpPackets++;

        TCPHeader *tcp = (TCPHeader *)(data + 14 + ip_header_len);

        uint16_t src_port = ntohs(tcp->src_port);
        uint16_t dst_port = ntohs(tcp->dst_port);

        cout << " | Protocol: TCP\n";
        cout << " | Src Port: " << src_port << endl;
        cout << " | Dst Port: " << dst_port << endl;

        int sbytes = pkt.data.size();
        int dbytes = pkt.data.size();

        string decision = callMLAPI("tcp", src_port, dst_port, sbytes, dbytes);

        cout << " | ML Decision: " << decision << endl;

        if (decision == "ATTACK")
        {
            cout << " ATTACK - ML BLOCKED PACKET\n";
            blockedPackets++;
            return true;
        }

        int tcp_header_len = 20;
        const uint8_t *payload = data + 14 + ip_header_len + tcp_header_len;
        int payload_len = pkt.data.size() - (14 + ip_header_len + tcp_header_len);

        if (src_port == 80 || dst_port == 80)
        {
            if (payload_len > 4 &&
                (strncmp((char *)payload, "GET", 3) == 0 ||
                 strncmp((char *)payload, "POST", 4) == 0))
            {
                cout << " | Application: HTTP\n";

                string http_data((char *)payload, payload_len);
                size_t pos = http_data.find("Host:");

                if (pos != string::npos)
                {
                    size_t end = http_data.find("\r\n", pos);
                    string host = http_data.substr(pos + 6, end - pos - 6);

                    cout << " | Host: " << host << endl;

                    if (isBlocked(host))
                    {
                        cout << " BLOCKED (HTTP)\n";
                        blockedPackets++;
                    }
                    else
                    {
                        cout << " ALLOWED\n";
                        allowedPackets++;
                    }
                }
            }
        }

        if (src_port == 443 || dst_port == 443)
        {
            cout << " | Application: HTTPS (TLS)\n";

            if (payload_len > 5 && payload[0] == 0x16)
            {
                int pos = 43;

                if (pos >= payload_len) return true;

                int session_len = payload[pos];
                pos += 1 + session_len;

                if (pos + 2 > payload_len) return true;

                int cipher_len = (payload[pos] << 8) | payload[pos + 1];
                pos += 2 + cipher_len;

                if (pos >= payload_len) return true;

                int comp_len = payload[pos];
                pos += 1 + comp_len;

                if (pos + 2 > payload_len) return true;

                int ext_len = (payload[pos] << 8) | payload[pos + 1];
                pos += 2;

                int end = pos + ext_len;

                while (pos + 4 <= end && pos + 4 <= payload_len)
                {
                    int type = (payload[pos] << 8) | payload[pos + 1];
                    int len  = (payload[pos + 2] << 8) | payload[pos + 3]; // FIXED
                    pos += 4;

                    if (type == 0x0000)
                    {
                        if (pos + 5 > payload_len) break;

                        int sni_len = (payload[pos + 3] << 8) | payload[pos + 4];
                        pos += 5;

                        string sni((char *)(payload + pos), sni_len);

                        cout << " | SNI: " << sni << endl;

                        if (isBlocked(sni))
                        {
                            cout << " BLOCKED (HTTPS)\n";
                            blockedPackets++;
                        }
                        else
                        {
                            cout << " ALLOWED\n";
                            allowedPackets++;
                        }
                        break;
                    }
                    pos += len;
                }
            }
        }
    }

    // ================= UDP =================
    else if (ip->protocol == 17)
    {
        udpPackets++;

        UDPHeader *udp = (UDPHeader *)(data + 14 + ip_header_len);

        uint16_t src_port = ntohs(udp->src_port);
        uint16_t dst_port = ntohs(udp->dst_port);

        cout << " | Protocol: UDP\n";
        cout << " | Src Port: " << src_port << endl;
        cout << " | Dst Port: " << dst_port << endl;

        int sbytes = pkt.data.size();
        int dbytes = pkt.data.size();

        string decision = callMLAPI("udp", src_port, dst_port, sbytes, dbytes);

        cout << " | ML Decision: " << decision << endl;

        if (decision == "ATTACK")
        {
            cout << " ATTACK - ML BLOCKED PACKET\n";
            blockedPackets++;
            return true;
        }

        if (src_port == 53 || dst_port == 53)
        {
            cout << " | Application: DNS\n";

            const uint8_t* dns_payload = data + 14 + ip_header_len + 8;
            int dns_len = pkt.data.size() - (14 + ip_header_len + 8);

            if (dns_len < 12) return true;

            string domain = extractDNSQuery(dns_payload, dns_len);

            if (!domain.empty())
            {
                cout << " | DNS Query: " << domain << endl;

                if (isBlocked(domain))
                {
                    cout << " BLOCKED (DNS)\n";
                    blockedPackets++;
                }
                else
                {
                    cout << " ALLOWED (DNS)\n";
                    allowedPackets++;
                }
            }
        }
    }

    cout << "\n";
    return true;
}

} // namespace CaptureService

