#include <vector>
#include <random>
#include <chrono>
#include <cstring>
#include "src\heversa_api.h"

// function to generate fake weights for the simulated clients
std::vector<std::vector<uint32_t>> simulate_weights(int num_clients, size_t update_len, uint32_t seed = 42) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(0, 1000);
    std::vector<std::vector<uint32_t>> client_weights(num_clients, std::vector<uint32_t>(update_len));
    for (int i = 0; i < num_clients; i++) {
        for (size_t j = 0; j < update_len; j++) {
            client_weights[i][j] = dist(rng);
        }
    }
    return client_weights;
}
//random dropouts
std::vector<int> simulate_dropouts(int num_clients, int num_dropouts) {
    std::vector<int> dropouts;
    for (int i = 0; i < num_dropouts && i < num_clients; i++) {
        dropouts.push_back(num_clients - 1 - i);
    }
    return dropouts;
}

bool is_node_dropped(int node_id, const std::vector<int>& dropouts) {
    for (int d : dropouts) {
        if (d == node_id) return true;
    }
    return false;
}