#include <stdio.h>
#include <string.h>
#include "common.h"
#include "node.h"
#include "server.h"
#include "ta.h"

// --- MOCK NETWORK BUFFERS ---
uint8_t server_inbox[MAX_NUM_CLIENTS][4096]; 
size_t server_inbox_len[MAX_NUM_CLIENTS];

uint8_t node_inbox[4096]; 
size_t node_inbox_len;

// --- MOCK I/O CALLBACKS ---
prot_ret_t mock_node_send(void* obj, const uint8_t* data, size_t len) {
    node_id_t id = *(node_id_t*)obj;
    memcpy(server_inbox[id], data, len);
    server_inbox_len[id] = len;
    return OK;
}

prot_ret_t mock_srv_send(void* obj, const uint8_t* data, size_t len) {
    memcpy(node_inbox, data, len);
    node_inbox_len = len;
    return OK;
}

prot_ret_t mock_srv_recv(void* obj, uint8_t* buff, size_t max_len, size_t* out_len) {
    node_id_t target_id = *(node_id_t*)obj; 
    if (server_inbox_len[target_id] > 0) {
        memcpy(buff, server_inbox[target_id], server_inbox_len[target_id]);
        *out_len = server_inbox_len[target_id];
        server_inbox_len[target_id] = 0; 
        return OK;
    }
    return ERROR;
}

prot_ret_t mock_node_recv(void* obj, uint8_t* buff, size_t max_len, size_t* out_len) {
    if (node_inbox_len > 0) {
        memcpy(buff, node_inbox, node_inbox_len);
        *out_len = node_inbox_len;
        return OK;
    }
    return ERROR;
}

int main() {
    printf("=== Starting HeVerSa Protocol Simulation (4 Nodes) ===\n");

    int N = 4; // Increased to 4 participants
    int K = 2; // Reconstruction Threshold

    // 1. Setup TA (Trusted Authority)
    ta_compute_offset(N, K, INITIAL_LINK);

    // 2. Setup Server
    server_t srv;
    srv_id_t server_id = 99;
    io_interface_t srv_io = { .send = mock_srv_send, .recv = mock_srv_recv };
    server_setup(&srv, server_id, srv_io);

    ta_send_global_masks(&srv, N, INITIAL_LINK);

    // 3. Setup Nodes
    node_t nodes[4]; // Array expanded to 4
    for (int i = 0; i < N; i++) {
        io_interface_t node_io = { .obj = &nodes[i].node_id, .send = mock_node_send, .recv = mock_node_recv };
        node_setup(&nodes[i], i, node_io);
        
        for(int j=0; j<UPDATE_LEN; j++) {
            nodes[i].data_update[j] = (i + 1) * 10; 
        }
        
        for(int k=0; k<N; k++) {
            if (k != i) node_set_add(&nodes[i].K_j, k);
        }
    }

    printf("\n--- PHASE 1: Local Updates ---\n");
    run_node_state(&nodes[0]); 
    run_node_state(&nodes[1]); 
    
    // -> WE INTENTIONALLY DO NOT RUN NODE 2 (DROPOUT SIMULATION) <-
    printf("[SIM] Node 2 unexpectedly dropped out!\n");

    run_node_state(&nodes[3]); // Node 3 successfully sends

    for (int i = 0; i < N; i++) {
        srv.io.obj = &nodes[i].node_id; 
        server_run_state(&srv);  
    }

    printf("\n--- PHASE 2: Request Shares ---\n");
    srv_state_req_shares(&srv);

    run_node_state(&nodes[0]); 
    run_node_state(&nodes[1]); 
    run_node_state(&nodes[3]); // Node 3 generates shares

    printf("\n--- PHASE 3: Recovery and Global Aggregation ---\n");
    srv.io.obj = &nodes[0].node_id;
    srv_state_wait_recovery(&srv);
    
    srv.io.obj = &nodes[1].node_id;
    srv_state_wait_recovery(&srv);

    srv.io.obj = &nodes[3].node_id;
    srv_state_wait_recovery(&srv); // Node 3 sends shares to server

    if (srv.current_state == srv_state_compute_global) {
        server_run_state(&srv); 
    } else {
        printf("[SIM ERROR] Server failed to recover the dropout!\n");
        return -1;
    }

    printf("\n--- PHASE 4: Verification ---\n");
    run_node_state(&nodes[0]); 
    run_node_state(&nodes[1]);
    run_node_state(&nodes[3]); // Node 3 verifies

    printf("\n=== Simulation Complete ===\n");
    return 0;
}