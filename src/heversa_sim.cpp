#include "heversa_sim.h"
#include "msg_type.h"
#include <stdio.h>
#include <memory>

void run_federated_round_sim(
    server_t* srv, 
    node_t* clients, 
    int num_clients, 
    uint32_t client_weights[][UPDATE_LEN], 
    uint32_t* final_out_model) 
{
    // --- PHASE 1: Collect Updates ---
    for (int i = 0; i < num_clients; i++) {
        auto update_msg = std::make_unique<node_local_update_t>();
        // 1. Client obfuscates
        client_mask_update(&clients[i], client_weights[i], update_msg.get());
        // 2. Server receives
        server_receive_update(srv, update_msg.get());
    }

    // --- ORCHESTRATOR: Check Dropouts ---
    node_set_t dropouts;
    auto server_drop_packet = std::make_unique<srv_dropout_list_t>();    
    // Server builds the signed packet
    server_broadcast_dropouts(srv, server_drop_packet.get(), &dropouts);
    
    // --- PHASE 2: Share Exchange (ALWAYS RUNS) ---
    for (int i = 0; i < num_clients; i++) {
        // Check if this specific client dropped out
        bool is_dropout = false;
        for(int d = 0; d < dropouts.node_count; d++) {
            if(dropouts.node_id[d] == i) is_dropout = true;
        }
        
        // Active clients consume the server packet and generate shares
        if (!is_dropout) {
            auto share_msg = std::make_unique<node_shares_msg_t>();
            memset(share_msg.get(), 0, sizeof(node_shares_msg_t)); 
            
            // Pass the authentic packet to the client
            client_compute_shares(&clients[i], server_drop_packet.get(), share_msg.get());
            
            if (share_msg->item_cnt > 0) {
                server_receive_shares(srv, share_msg.get());
            }
        }
    }

    // --- PHASE 3: Finalize ---
    server_aggregate_updates(srv, final_out_model);
}