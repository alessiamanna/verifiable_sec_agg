#include <stdio.h>
#include <string.h>
#include "heversa_api.h"

#define NUM_CLIENTS 4
#define THRESHOLD 2

int main() {
    printf("=== Starting HeVerSa API (WITH DROPOUT SIMULATION) ===\n\n");

    server_t srv;
    memset(&srv, 0, sizeof(server_t));
    srv.srv_id = 99;

    node_t clients[NUM_CLIENTS];
    for (int i = 0; i < NUM_CLIENTS; i++) {
        memset(&clients[i], 0, sizeof(node_t));
    }

    // 1. Setup Phase
    ta_setup_protocol(NUM_CLIENTS, THRESHOLD, &srv);
    for (int i = 0; i < NUM_CLIENTS; i++) {
        client_setup(&clients[i], i);
    }

    // 2. Input Weights (C0=10, C1=20, C2=30, C3=40)
    uint32_t client_weights[NUM_CLIENTS][UPDATE_LEN];
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
        node_local_update_t update_msg;
        client_mask_update(&clients[i], client_weights[i], &update_msg);

        // 🚨 SIMULATE DROPOUT: We skip sending Node 2's packet to the Server
        if (i == 2) {
            printf("[Orchestrator] SIMULATING DROPOUT: Dropping Client %d's update!\n", i);
            continue; 
        }

        server_receive_update(&srv, &update_msg);
    }

    // ==========================================
    // PHASE 2: Dropout Recovery
    // ==========================================
    printf("\n--- PHASE 2: Share Exchange ---\n");
    node_set_t dropouts;
    srv_dropout_list_t server_drop_packet;

    // Server realizes Node 2 is missing and generates the signed dropout packet
    server_broadcast_dropouts(&srv, &server_drop_packet, &dropouts);

    for (int i = 0; i < NUM_CLIENTS; i++) {
        // Check if this specific client is in the dropout list
        bool is_dropout = false;
        for(int d = 0; d < dropouts.node_count; d++) {
            if(dropouts.node_id[d] == i) is_dropout = true;
        }

        // Only active clients generate shares
        if (!is_dropout) {
            node_shares_msg_t share_msg;
            memset(&share_msg, 0, sizeof(node_shares_msg_t)); 

            // Pass the authentic packet to the client
            client_compute_shares(&clients[i], &server_drop_packet, &share_msg);

            // Feed shares back to server
            if (share_msg.item_cnt > 0) {
                server_receive_shares(&srv, &share_msg);
            }
        }
    }

    // ==========================================
    // PHASE 3: Finalize
    // ==========================================
    printf("\n--- PHASE 3: Final Aggregation ---\n");
    uint32_t final_model[UPDATE_LEN];
    server_aggregate_updates(&srv, final_model);

    printf("\n=== FINAL UNMASKED WEIGHTS ===\n");
    for (int j = 0; j < 4; j++) { 
        printf("Feature[%d] = %u\n", j, final_model[j]);
    }
    printf("...\nExpected value: 70\n");

    return 0;
}