#include <stdio.h>
#include <string.h>
#include <memory>
#include <vector>
#include <cstdlib>
#include "heversa_api.h"

#define NUM_CLIENTS 10
#define THRESHOLD 4
#define TEST_UPDATE_LEN 35

int main(int argc, char* argv[]) {
    size_t update_len = 16;
    int num_clients = 10;
    int threshold = 4;
    if (argc > 1) {
        update_len = static_cast<size_t>(std::strtoul(argv[1], nullptr, 10));
    }
    if (argc > 2) {
        num_clients = std::atoi(argv[2]);
    }
    if (argc > 3) {
        threshold = std::atoi(argv[3]);
    }
    if (num_clients > MAX_NUM_CLIENTS) {
        printf("[ERROR] num_clients (%d) exceeds MAX_NUM_CLIENTS (%d)\n", num_clients, MAX_NUM_CLIENTS);
        return 1;
    }
    printf("=== Starting HeVerSa Simulation ===\n");
    printf("Parameters: update_len = %zu, num_clients = %d, threshold = %d\n\n", update_len, num_clients, threshold);
    server_t srv;
    srv.srv_id = 99;

    auto clients = std::make_unique<node_t[]>(num_clients);

    ta_setup_protocol(num_clients, threshold, update_len, &srv);
    for (int i = 0; i < num_clients; i++) {
        client_setup(&clients[i], i, update_len);
    }
    

    std::vector<std::vector<uint32_t>> client_weights(num_clients, std::vector<uint32_t>(update_len));
    for (int i = 0; i < num_clients; i++) {
        for (int j = 0; j < update_len; j++) {
            client_weights[i][j] = (i + 1) * 10; 
        }
    }

    // ==========================================
    // PHASE 1: Collect Updates
    // ==========================================
    printf("--- PHASE 1: Local Updates ---\n");
    for (int i = 0; i < num_clients; i++) {
        auto update_msg = std::make_unique<node_local_update_t>();
        
        client_mask_update(&clients[i], client_weights[i].data(), update_len, update_msg.get());

        if (i == 2 || i == 5 || i == 8) {
            printf("[Orchestrator] SIMULATING DROPOUT: Dropping Client %d's update!\n", i);
            continue; 
        }

        server_receive_update(&srv, update_msg.get());
    }

    // ==========================================
    // PHASE 2: Dropout Recovery
    // ==========================================
    node_set_t dropouts;
    auto server_drop_packet = std::make_unique<srv_dropout_list_t>();

    server_broadcast_dropouts(&srv, server_drop_packet.get(), &dropouts);

    // ==========================================
    // PHASE 2.1: Consistency Check
    // ==========================================
    printf("\n--- PHASE 2.1: Consistency Check ---\n");
    bool cc_passed[num_clients];
    for (int i = 0; i < num_clients; i++) cc_passed[i] = false;

    for (int i = 0; i < num_clients; i++) {
        bool is_dropout = false;
        for(int d = 0; d < dropouts.node_count; d++) {
            if(dropouts.node_id[d] == i) is_dropout = true;
        }
        if (is_dropout) continue;

        node_cc_msg_t cc_msg;
        client_compute_cc_value(&clients[i], server_drop_packet.get(), &cc_msg);
        server_receive_cc_value_msg(&srv, &cc_msg);
    }

    srv_cc_result_t cc_result;
    bool cc_ready = server_finalize_cc_result(&srv, &cc_result);

    if (!cc_ready) {
        printf("[SERVER] Not enough consistency check values collected, aborting round.\n");
    } else {
        for (int i = 0; i < num_clients; i++) {
            bool is_dropout = false;
            for(int d = 0; d < dropouts.node_count; d++) {
                if(dropouts.node_id[d] == i) is_dropout = true;
            }
            if (is_dropout) continue;

            cc_passed[i] = client_verify_cc_result(&clients[i], server_drop_packet.get(), &cc_result);
        }
    }

    // ==========================================
    // PHASE 2.2: Share Exchange
    // ==========================================
    printf("\n--- PHASE 2.2: Share Exchange ---\n");
    for (int i = 0; i < num_clients; i++) {
        bool is_dropout = false;
        for(int d = 0; d < dropouts.node_count; d++) {
            if(dropouts.node_id[d] == i) is_dropout = true;
        }

        if (!is_dropout && cc_passed[i]) {
            auto share_msg = std::make_unique<node_shares_msg_t>();
            client_compute_shares(&clients[i], server_drop_packet.get(), share_msg.get());

            if (share_msg->item_cnt > 0) {
                server_receive_shares(&srv, share_msg.get());
            }
        }
    }

    // ==========================================
    // PHASE 3: Finalize
    // ==========================================
    printf("\n--- PHASE 3: Final Aggregation ---\n");
    auto final_model = std::make_unique<uint32_t[]>(update_len);
    server_aggregate_updates(&srv, final_model.get());

    printf("\n=== FINAL UNMASKED WEIGHTS ===\n");
    for (int j = 0; j < 4 && j < update_len; j++) { 
        printf("Feature[%d] = %u\n", j, final_model[j]);
    }
    
    printf("...\nExpected value: %d\n", (num_clients >= 10) ? 370 : 0);
    return 0;
}
