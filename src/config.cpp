#include "config.hpp"

#include <windows.h>

#include <shellapi.h>

#include <optional>
#include <ranges>
#include <span>
#include <string_view>

#include "buildconfig.hpp"
#include "log.hpp"
#include "utils.hpp"

static constexpr std::string_view VERBOSE_FLAG    = "--layered-verbose";
static constexpr std::string_view DEVMODE_FLAG    = "--layered-devmode";
static constexpr std::string_view DISABLE_FLAG    = "--layered-disable";
static constexpr std::string_view ALLOWLIST_FLAG  = "--layered-allowlist=";
static constexpr std::string_view BLOCKLIST_FLAG  = "--layered-blocklist=";
static constexpr std::string_view LOGFILE_FLAG    = "--layered-logfile=";
static constexpr std::string_view MOD_FOLDER_FLAG = "--layered-data-mods-folder=";
static constexpr std::string_view NETWORK_HOOK_FLAG = "--layered-network-hook";
static constexpr std::string_view NETWORK_IP_FLAG = "--layered-network-ip=";
static constexpr std::string_view NETWORK_SUBNET_FLAG = "--layered-network-subnet=";

config_t config;

config_t::config_t()
    : verbose_logs(g_build_config.verbose_logs)
    , developer_mode(g_build_config.developer_mode) {
    set_mod_folder("./data_mods");
    if (g_build_config.external_logfile)
        logfile = DEFAULT_LOGFILE;
}

static void parse_list(std::string_view arg, std::set<istring>& dest) {
    for (const auto el : std::views::split(arg, std::string_view(",")))
        // need to cast to string_view as the range can't directly construct a string
        dest.emplace(istring_view(el));
}

void load_config() {
    config = config_t();

    int argc;
    auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        log_warning("Couldn't fetch commandline args!");
        return;
    }

    std::span args(argv, argv + argc);
    // so close to just pulling in a third party argparsing lib...
    for (auto warg : args) {
        // narrowing
        std::string _arg(warg, warg + wcslen(warg));
        std::string_view arg(_arg);

        if (arg == VERBOSE_FLAG) {
            config.verbose_logs = true;
        } else if (arg == DEVMODE_FLAG) {
            config.developer_mode = true;
        } else if (arg == DISABLE_FLAG) {
            config.disable = true;
        } else if (arg == NETWORK_HOOK_FLAG) {
            config.network_hook = true;
        } else if (arg.starts_with(ALLOWLIST_FLAG)) {
            arg.remove_prefix(ALLOWLIST_FLAG.size());
            parse_list(arg, config.allowlist);
        } else if (arg.starts_with(BLOCKLIST_FLAG)) {
            arg.remove_prefix(BLOCKLIST_FLAG.size());
            parse_list(arg, config.blocklist);
        } else if (arg.starts_with(LOGFILE_FLAG)) {
            arg.remove_prefix(LOGFILE_FLAG.size());
            // correct format: --layered-logfile=whatever.log
            if (!arg.empty()) {
                config.logfile = arg;
            }
        } else if (arg.starts_with(MOD_FOLDER_FLAG)) {
            arg.remove_prefix(MOD_FOLDER_FLAG.size());
            // correct format: --layered-data-mods-folder=./my_mods
            if (arg.starts_with("./")) {
                config.set_mod_folder(std::string(arg));
            }
        } else if (arg.starts_with(NETWORK_IP_FLAG)) {
            arg.remove_prefix(NETWORK_IP_FLAG.size());
            if (!arg.empty()) {
                config.network_ip = arg;
            }
        } else if (arg.starts_with(NETWORK_SUBNET_FLAG)) {
            arg.remove_prefix(NETWORK_SUBNET_FLAG.size());
            if (!arg.empty()) {
                config.network_subnet = arg;
            }
        }
    }
}

void print_config() {
    // clang-format off
    log_info("Options: {}={} {}={} {}={} {}={} {}{} {}{} {}{} {}{} {}{} {}{}",
        VERBOSE_FLAG, config.verbose_logs,
        DEVMODE_FLAG, config.developer_mode,
        DISABLE_FLAG, config.disable,
        NETWORK_HOOK_FLAG, config.network_hook,
        LOGFILE_FLAG, config.logfile,
        ALLOWLIST_FLAG, config.allowlist,
        BLOCKLIST_FLAG, config.blocklist,
        MOD_FOLDER_FLAG, config.get_mod_folder(),
        NETWORK_IP_FLAG, config.network_ip,
        NETWORK_SUBNET_FLAG, config.network_subnet
    );
    // clang-format on
}
