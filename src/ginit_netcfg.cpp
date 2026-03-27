#include "network.h"
#include "signals.h"

#include <csignal>

namespace {

void handle_stop_signal(int) {
    g_stop_sig = 1;
}

} // namespace

int main() {
    struct sigaction action {};
    action.sa_handler = handle_stop_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
    signal(SIGPIPE, SIG_IGN);
    return ConfigureNetwork();
}
