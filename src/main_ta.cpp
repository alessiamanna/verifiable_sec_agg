#include <stdio.h>
#include <string.h>
#include <memory>
#include "heversa_api.h"

#define NUM_CLIENTS 10
#define THRESHOLD 4

int main() {
    printf("=== Starting HeVerSa API (10 Clients, 3 Dropouts) ===\n\n");

    server_t srv;
    memset(&srv, 0, sizeof(server_t));
    srv.srv_id = 99;


    auto clients = std::make_unique<node_t[]>(NUM_CLIENTS);
    for (int i = 0; i < NUM_CLIENTS; i++) {
        memset(&clients[i], 0, sizeof(node_t));
    }

    ta_setup_protocol(NUM_CLIENTS, THRESHOLD, &srv);
    for (int i = 0; i < NUM_CLIENTS; i++) {
        client_setup(&clients[i], i);
    }


    auto client_weights = std::make_unique<uint32_t[][UPDATE_LEN]>(NUM_CLIENTS);
    for (int i = 0; i < NUM_CLIENTS; i++) {
        for (int j = 0; j < UPDATE_LEN; j++) {
            client_weights[i][j] = (i + 1) * 10; 
        }
    }

    // ==========================================
    // PHASE 1: Collect Updates
    // ==========================================
    printf("--- PHASE 1: Local Updates ---\n");
    for (int i = 0; i < NUM_CLIENTS; i++) {

        auto update_msg = std::make_unique<node_local_update_t>();
        
        client_mask_update(&clients[i], client_weights[i], update_msg.get());


        if (i == 2 || i == 5 || i == 8) {
            printf("[Orchestrator] SIMULATING DROPOUT: Dropping Client %d's update!\n", i);
            continue; 
        }

        server_receive_update(&srv, update_msg.get());
    }

    // ==========================================
    // PHASE 2: Dropout Recovery
    // ==========================================
    printf("\n--- PHASE 2: Share Exchange ---\n");
    node_set_t dropouts;
    auto server_drop_packet = std::make_unique<srv_dropout_list_t>();

    server_broadcast_dropouts(&srv, server_drop_packet.get(), &dropouts);

    for (int i = 0; i < NUM_CLIENTS; i++) {
        bool is_dropout = false;
        for(int d = 0; d < dropouts.node_count; d++) {
            if(dropouts.node_id[d] == i) is_dropout = true;
        }

        if (!is_dropout) {
            auto share_msg = std::make_unique<node_shares_msg_t>();
            memset(share_msg.get(), 0, sizeof(node_shares_msg_t)); 

            // Pass the authentic packet to the client
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
    auto final_model = std::make_unique<uint32_t[]>(UPDATE_LEN);
    server_aggregate_updates(&srv, final_model.get());

    printf("\n=== FINAL UNMASKED WEIGHTS ===\n");
    for (int j = 0; j < 4; j++) { 
        printf("Feature[%d] = %u\n", j, final_model[j]);
    }
    printf("...\nExpected value: 370\n");

    return 0;
}