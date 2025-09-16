#pragma once

#include <stdint.h>
#include "duckdb_extension.h"

// Constants
static const int32_t HEX_BITSIZE = 4;
static const int32_t MAX_QUIBBLE_DIGITS = 4;
static const size_t QUIBBLES_PER_HALF = 4;
static const uint64_t IPV4_NETWORK_MASK = 0xffffffff;
static const duckdb_uhugeint IPV6_NETWORK_MASK = {0xffffffffffffffff, 0xffffffffffffffff};

static const size_t IPV4_DEFAULT_MASK = 32;
static const size_t IPV6_DEFAULT_MASK = 128;
static const size_t IPV6_QUIBBLE_BITS = 16;
static const size_t IPV6_NUM_QUIBBLE = 8;

// Enum for IP address type
typedef enum {
    IP_ADDRESS_INVALID = 0,
    IP_ADDRESS_V4 = 1,
    IP_ADDRESS_V6 = 2
} IPAddressType;

// IPAddress struct
typedef struct {
    IPAddressType type;
    duckdb_uhugeint address;
    uint16_t mask;
} IPAddress;

// Try to parse an IP address from a string.
// If error_message is not NULL, it will be set to an error message on failure.
// The error_message does not need to be freed, it is a static string.
IPAddress ipaddress_from_string(const char* buffer, size_t buffer_size, char **error_message);

// Returns length of string written to buffer. Returns 0 if buffer is too small.
size_t ipaddress_to_string(const IPAddress *ip, char* buffer, size_t buffer_size);

IPAddress ipaddress_netmask(const IPAddress *ip);
IPAddress ipaddress_network(const IPAddress *ip);
IPAddress ipaddress_broadcast(const IPAddress *ip);

