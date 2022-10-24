#pragma once

#define IP 0x0800

#pragma pack(push, 1)
struct EthHdr
{
    char dmac_[6];
    char smac_[6];
    
};
