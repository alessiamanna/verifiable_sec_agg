#include "heversa_sim.h"
#include "msg_type.h"
#include <stdio.h>
#include <memory>

void run_federated_round_sim(
    server_t* srv, 
    node_t* clients, 
    int num_clients, 
    size_t update_len,
    const uint32_t* client_weights, 
    uint32_t* final_out_model) 
{
    // --- PHASE 1: Collect Updates ---
    for (int i = 0; i < num_clients; i++) {
        auto update_msg = std::make_unique<node_local_update_t>();
        // 1. Client obfuscates
        client_mask_update(&clients[i], &client_weights[i * update_len], update_len, update_msg.get());
        // 2. Server receives
        server_receive_update(srv, update_msg.get());
    }

    // --- ORCHESTRATOR: Check Dropouts ---
    node_set_t dropouts;
    auto server_drop_packet = std::make_unique<srv_dropout_list_t>();
    // Server builds the signed packet
    server_broadcast_dropouts(srv, server_drop_packet.get(), &dropouts);

    // --- PHASE 1.5: Consistency Check ---
    auto cc_passed = std::make_unique<bool[]>(num_clients);
    for (int i = 0; i < num_clients; i++) cc_passed[i] = false;

    for (int i = 0; i < num_clients; i++) {
        bool is_dropout = false;
        for(int d = 0; d < dropouts.node_count; d++) {
            if(dropouts.node_id[d] == i) is_dropout = true;
        }
        if (is_dropout) continue;

        node_cc_msg_t cc_msg;
        client_compute_cc_value(&clients[i], server_drop_packet.get(), &cc_msg);
        server_receive_cc_value_msg(srv, &cc_msg);
    }

    srv_cc_result_t cc_result;
    bool cc_ready = server_finalize_cc_result(srv, &cc_result);

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

    // --- PHASE 2: Share Exchange ---
    for (int i = 0; i < num_clients; i++) {
        bool is_dropout = false;
        for(int d = 0; d < dropouts.node_count; d++) {
            if(dropouts.node_id[d] == i) is_dropout = true;
        }

        if (!is_dropout && cc_passed[i]) {
            auto share_msg = std::make_unique<node_shares_msg_t>();
            client_compute_shares(&clients[i], server_drop_packet.get(), share_msg.get());

            if (share_msg->item_cnt > 0) {
                server_receive_shares(srv, share_msg.get());
            }
        }
    }

    // --- PHASE 3: Finalize ---
    server_aggregate_updates(srv, final_out_model);
}
