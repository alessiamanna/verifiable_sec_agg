#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "node.h"
#include "server.h"
#include "common.h"
#include "common_share.h"
#include "msg_type.h"
#include "puf_utils.h"
#include "puf_data.h"
#include "ta.h"


#define NET_BUF_SIZE 8192 

typedef struct {
    uint8_t buffer[NET_BUF_SIZE];
    size_t len;
    int has_data;
} mock_io_t;

prot_ret_t mock_send(void* obj, const uint8_t* data, size_t len) {
    mock_io_t* io = (mock_io_t*)obj;
    if (len > NET_BUF_SIZE) {
        printf("[NET ERROR] Packet too big\n"); return ERROR;
    }
    memcpy(io->buffer, data, len);
    io->len = len;
    io->has_data = 1;
    return OK;
}

prot_ret_t mock_recv(void* obj, uint8_t* data, size_t max_len, size_t* out_len) {
    mock_io_t* io = (mock_io_t*)obj;
    if (!io->has_data) return ERROR;
    size_t to_copy = (io->len < max_len) ? io->len : max_len;
    memcpy(data, io->buffer, to_copy);
    *out_len = to_copy;
    io->has_data = 0; 
    return OK;
}

void vec_add(update_t* dest, update_t* src){
    for(int i=0; i<UPDATE_LEN; i++) dest[i] += src[i];
}

void print_vec(const char* label, update_t* v){
    printf("%s: [%u, %u, ...]\n", label, (uint32_t)v[0], (uint32_t)v[1]);
}

int main() {
    printf("\n=== SECURE AGGREGATION: 4 NODES TEST (Node 1 Dies) ===\n");

    int N = 4;             
    int DROPOUT_NODE = 1; 
    int K = 2;            
    puf_index_t base_idx = 0; 

    printf("\n[PHASE 1] TA Setup\n");
    server_db_init();
    ta_compute_offset(N, K, base_idx); 

   
    mock_io_t srv_io_obj = {0};
    io_interface_t srv_io = { .obj = &srv_io_obj, .send = mock_send, .recv = mock_recv };
    
    server_t srv;
    server_setup(&srv, 0xAA, srv_io);

    ta_send_global_masks(&srv, N, base_idx);

    node_t nodes[N];
    mock_io_t node_io[N];
    update_t expected_result[UPDATE_LEN] = {0};

    for(int i=0; i<N; i++){
    
        memset(&node_io[i], 0, sizeof(mock_io_t));
        io_interface_t nio = { .obj = &node_io[i], .send = mock_send, .recv = mock_recv };
        
        node_setup(&nodes[i], i, nio);
        
      
        for(int j=0; j<N; j++) {
            if(i != j) node_set_add(&nodes[i].K_j, j);
        }
        
        nodes[i].current_link_ta = base_idx;
        nodes[i].current_link_srv = INITIAL_LINK;
        
        for(int k=0; k<UPDATE_LEN; k++) nodes[i].data_update[k] = (i+1)*10;
        
        if(i != DROPOUT_NODE) {
            vec_add(expected_result, nodes[i].data_update);
            printf("   Node %d is Alive (Data: %d)\n", i, nodes[i].data_update[0]);
        } else {
            printf("   Node %d WILL DIE (Dropout)\n", i);
        }
    }
    print_vec("   Expected Sum", expected_result);

    printf("\n[PHASE 4] Upload Updates\n");
    
    for(int i=0; i<N; i++){
        if (i == DROPOUT_NODE) continue; 

        node_state_compute_update(&nodes[i]);

        memcpy(srv_io_obj.buffer, node_io[i].buffer, node_io[i].len);
        srv_io_obj.len = node_io[i].len;
        srv_io_obj.has_data = 1;

        srv_state_wait_updates(&srv);
        
        node_io[i].has_data = 0;
    }
    printf("   Server Participants (J_prime): %d (Expected 3)\n", srv.J_prime_set.node_count);

    printf("\n[PHASE 5] Detect Dropouts\n");
    srv.current_state = srv_state_req_shares;
    srv_state_req_shares(&srv); 
    
    printf("   Dropouts Detected: %d (Expected 1)\n", srv.Z_set.node_count);
    
    uint8_t broadcast_buf[NET_BUF_SIZE];
    size_t broadcast_len = srv_io_obj.len;
    memcpy(broadcast_buf, srv_io_obj.buffer, broadcast_len);

    printf("\n[PHASE 6] Recovery Phase\n");

    for(int i=0; i<N; i++){
        if (i == DROPOUT_NODE) continue; 

        memcpy(node_io[i].buffer, broadcast_buf, broadcast_len);
        node_io[i].len = broadcast_len;
        node_io[i].has_data = 1;

        node_state_wait_for_server(&nodes[i]);

        memcpy(srv_io_obj.buffer, node_io[i].buffer, node_io[i].len);
        srv_io_obj.len = node_io[i].len;
        srv_io_obj.has_data = 1;

        srv_state_wait_recovery(&srv);
        printf("   -> Node %d recovery shares sent.\n", i);
    }

    printf("\n[PHASE 7] Finalize\n");
    srv_state_compute_global(&srv); 
    printf("\n[PHASE 8] Verify Result\n");
    
    memcpy(node_io[0].buffer, srv_io_obj.buffer, srv_io_obj.len);
    node_io[0].len = srv_io_obj.len;
    node_io[0].has_data = 1;

    node_state_wait_final(&nodes[0]);

    int match = 1;
    for(int k=0; k<UPDATE_LEN; k++){
        if(nodes[0].data_update[k] != expected_result[k]) match = 0;
    }

    print_vec("Expected", expected_result);
    print_vec("Received", nodes[0].data_update);

    if(match) printf("\n✅ SUCCESS: 4-Node Test Passed!\n");
    else      printf("\n❌ FAILED: Sum Mismatch.\n");

    return 0;
}