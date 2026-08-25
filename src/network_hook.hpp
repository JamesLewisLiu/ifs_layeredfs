#pragma once

// Registers the optional IPv4 adapter filtering hooks. The hooks are enabled
// together with the rest of LayeredFS' MinHook hooks in hook.cpp.
void install_network_hooks();
