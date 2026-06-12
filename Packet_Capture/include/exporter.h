#pragma once
#include <vector>
#include <string>
#include "packet.h"

class Exporter {
public:
    static void exportToJS(const std::vector<CaptureService::Packet>& packets, const std::string& filename);
};

