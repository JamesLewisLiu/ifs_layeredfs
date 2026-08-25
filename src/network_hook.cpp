#include "network_hook.hpp"

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <optional>

#include "3rd_party/MinHook.h"
#include "config.hpp"
#include "log.hpp"

namespace {

using get_adapters_info_t = decltype(GetAdaptersInfo)*;
using get_ip_addr_table_t = decltype(GetIpAddrTable)*;
using bind_t = decltype(bind)*;

get_adapters_info_t get_adapters_info_orig = nullptr;
get_ip_addr_table_t get_ip_addr_table_orig = nullptr;
bind_t bind_orig = nullptr;

std::optional<in_addr> preferred_network;
std::optional<in_addr> preferred_subnet;

bool is_valid_row(const MIB_IPADDRROW& row) {
    static const auto loopback = inet_addr("127.0.0.1");
    return row.dwAddr != 0 && row.dwAddr != loopback;
}

bool matches_preference(const MIB_IPADDRROW& row) {
    if (!preferred_network || !preferred_subnet || !is_valid_row(row)) {
        return false;
    }
    return (row.dwAddr & row.dwMask) == preferred_network->s_addr &&
           row.dwMask == preferred_subnet->s_addr;
}

std::optional<DWORD> default_route_interface() {
    ULONG size = 0;
    auto result = GetIpForwardTable(nullptr, &size, TRUE);
    if (result != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        return std::nullopt;
    }

    auto* table = static_cast<PMIB_IPFORWARDTABLE>(malloc(size));
    if (!table) {
        return std::nullopt;
    }
    result = GetIpForwardTable(table, &size, TRUE);
    if (result != NO_ERROR || table->dwNumEntries == 0) {
        free(table);
        return std::nullopt;
    }

    const DWORD interface_index = table->table[0].dwForwardIfIndex;
    free(table);
    return interface_index;
}

MIB_IPADDRROW* select_ip_row(PMIB_IPADDRTABLE table) {
    if (!table || table->dwNumEntries == 0) {
        return nullptr;
    }

    for (DWORD index = 0; index < table->dwNumEntries; index++) {
        if (matches_preference(table->table[index])) {
            return &table->table[index];
        }
    }

    if (const auto interface_index = default_route_interface()) {
        for (DWORD index = 0; index < table->dwNumEntries; index++) {
            auto& row = table->table[index];
            if (row.dwIndex == *interface_index && is_valid_row(row)) {
                return &row;
            }
        }
    }

    for (DWORD index = 0; index < table->dwNumEntries; index++) {
        if (is_valid_row(table->table[index])) {
            return &table->table[index];
        }
    }
    return nullptr;
}

void keep_only_ip_row(PMIB_IPADDRTABLE table, MIB_IPADDRROW* row) {
    if (!table || !row) {
        return;
    }
    static bool logged = false;
    if (!logged) {
        in_addr address{};
        address.s_addr = row->dwAddr;
        log_info("Network hook selected IPv4 address {}", inet_ntoa(address));
        logged = true;
    }
    table->table[0] = *row;
    table->dwNumEntries = 1;
}

PIP_ADAPTER_INFO select_adapter(PIP_ADAPTER_INFO adapters) {
    if (!adapters) {
        return nullptr;
    }

    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        const auto address = inet_addr(adapter->IpAddressList.IpAddress.String);
        const auto subnet = inet_addr(adapter->IpAddressList.IpMask.String);
        MIB_IPADDRROW row{};
        row.dwAddr = address;
        row.dwMask = subnet;
        if (matches_preference(row)) {
            return adapter;
        }
    }

    if (const auto interface_index = default_route_interface()) {
        for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->Index == *interface_index &&
                adapter->IpAddressList.IpAddress.String[0] != '\0' &&
                adapter->IpAddressList.IpAddress.String[0] != '0') {
                return adapter;
            }
        }
    }

    for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
        const auto address = inet_addr(adapter->IpAddressList.IpAddress.String);
        if (address != 0 && address != inet_addr("127.0.0.1")) {
            return adapter;
        }
    }
    return nullptr;
}

ULONG WINAPI get_adapters_info_hook(PIP_ADAPTER_INFO adapters, PULONG buffer_size) {
    const auto result = get_adapters_info_orig(adapters, buffer_size);
    if (result != ERROR_SUCCESS || !adapters) {
        return result;
    }

    if (auto* selected = select_adapter(adapters)) {
        static bool logged = false;
        if (!logged) {
            log_info("Network hook selected adapter: {}, {}", selected->AdapterName, selected->Description);
            logged = true;
        }
        memcpy(adapters, selected, sizeof(*adapters));
        adapters->Next = nullptr;
    } else {
        log_warning("Network hook could not find a valid IPv4 adapter");
    }
    return result;
}

DWORD WINAPI get_ip_addr_table_hook(PMIB_IPADDRTABLE table, PULONG table_size, BOOL order) {
    const auto input_size = table_size ? *table_size : 0;
    auto result = get_ip_addr_table_orig(table, table_size, order);

    if (result == NO_ERROR) {
        keep_only_ip_row(table, select_ip_row(table));
        return result;
    }
    if (result != ERROR_INSUFFICIENT_BUFFER || !table || !table_size) {
        return result;
    }

    const auto one_row_size = offsetof(MIB_IPADDRTABLE, table) + sizeof(MIB_IPADDRROW);
    if (input_size < one_row_size) {
        return result;
    }

    const auto full_size = *table_size;
    auto* full_table = static_cast<PMIB_IPADDRTABLE>(malloc(full_size));
    if (!full_table) {
        return result;
    }

    auto queried_size = full_size;
    if (get_ip_addr_table_orig(full_table, &queried_size, order) == NO_ERROR) {
        if (auto* selected = select_ip_row(full_table)) {
            table->table[0] = *selected;
            table->dwNumEntries = 1;
            *table_size = one_row_size;
            result = NO_ERROR;
        }
    }
    free(full_table);
    return result;
}

int WINAPI bind_hook(SOCKET socket, const sockaddr* name, int name_length) {
    if (!name || name_length < static_cast<int>(sizeof(sockaddr_in)) || name->sa_family != AF_INET) {
        return bind_orig(socket, name, name_length);
    }

    auto address = *reinterpret_cast<const sockaddr_in*>(name);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    return bind_orig(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
}

bool parse_ipv4(const std::string& text, in_addr* output) {
    return InetPtonA(AF_INET, text.c_str(), output) == 1;
}

} // namespace

void install_network_hooks() {
    if (!config.network_hook) {
        return;
    }

    if (config.network_ip.has_value() != config.network_subnet.has_value()) {
        log_warning("Network hook needs both --layered-network-ip and --layered-network-subnet; using default route");
    } else if (config.network_ip) {
        in_addr network{};
        in_addr subnet{};
        if (!parse_ipv4(*config.network_ip, &network) || !parse_ipv4(*config.network_subnet, &subnet)) {
            log_warning("Network hook has an invalid IPv4 address or subnet; using default route");
        } else {
            network.s_addr &= subnet.s_addr;
            preferred_network = network;
            preferred_subnet = subnet;
            log_info("Network hook preference: {}/{}", *config.network_ip, *config.network_subnet);
        }
    }

    const auto install = [](LPCWSTR module, LPCSTR procedure, LPVOID hook, LPVOID* original) {
        if (MH_CreateHookApi(module, procedure, hook, original) != MH_OK) {
            log_warning("Network hook could not hook {}", procedure);
        }
    };

    install(L"iphlpapi.dll", "GetAdaptersInfo", reinterpret_cast<LPVOID>(get_adapters_info_hook),
        reinterpret_cast<LPVOID*>(&get_adapters_info_orig));
    install(L"iphlpapi.dll", "GetIpAddrTable", reinterpret_cast<LPVOID>(get_ip_addr_table_hook),
        reinterpret_cast<LPVOID*>(&get_ip_addr_table_orig));
    install(L"ws2_32.dll", "bind", reinterpret_cast<LPVOID>(bind_hook), reinterpret_cast<LPVOID*>(&bind_orig));
}
