#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mqueue.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>


#include "dev_protocol.h"
#include "srv_protocol.h" 

// --- CONFIGURATION ---
#define Q_UPLINK   "/puf_uplink_v2"
#define Q_DOWNLINK "/puf_downlink_v2"

#ifndef MAX_NUM_CLIENTS
#define MAX_NUM_CLIENTS 4
#endif

// --- 1. CONTEXT WRAPPER ---
typedef struct {
    mqd_t q_up;    // Small packets (Dev -> Srv)
    mqd_t q_down;  // Large packets (Srv -> Dev)
    int my_id;     // Used by client to filter messages
} QueueContext;

// --- 2. SERVER CALLBACKS ---

// Server Recv: Reads from UPLINK (Device Packets)
prot_ret_t srv_mqueue_recv(void* obj, uint8_t* buffer, size_t max_len, size_t* out_len){
    QueueContext* ctx = (QueueContext*)obj;
    
    // Blocking read
    ssize_t bytes = mq_receive(ctx->q_up, (char*)buffer, max_len, NULL);
    
    if(bytes < 0) {
        perror("[SRV-RX] mq_receive failed");
        return ERROR;
    }
    *out_len = (size_t)bytes;
    return OK;
}

// Server Send: Writes to DOWNLINK (Server Packets)
prot_ret_t srv_mqueue_send(void* obj, const uint8_t* data, size_t len){
    QueueContext* ctx = (QueueContext*)obj;
    
    if (mq_send(ctx->q_down, (const char*)data, len, 0) == -1) {
        perror("[SRV-TX] mq_send failed");
        return ERROR;
    }
    return OK;
}

// --- 3. CLIENT CALLBACKS ---

// Client Send: Writes to UPLINK
prot_ret_t cli_mqueue_send(void* obj, const uint8_t* data, size_t len){
    QueueContext* ctx = (QueueContext*)obj;
    if(mq_send(ctx->q_up, (const char*)data, len, 0) == -1) {
        perror("[CLI-TX] Send failed");
        return ERROR;
    }
    return OK;
}

// Client Recv: Reads from DOWNLINK with ID Filtering (Bus Simulation)
prot_ret_t cli_mqueue_recv(void* obj, uint8_t* buffer, size_t max_len, size_t* out_len){
    QueueContext* ctx = (QueueContext*)obj;
    srv_pckt_t temp_pckt;

    while(1) {
        // 1. Read a message from the queue
        ssize_t bytes = mq_receive(ctx->q_down, (char*)&temp_pckt, sizeof(srv_pckt_t), NULL);
        
        if(bytes < 0) return ERROR;

        // 2. Check if this packet is meant for ME
        if(temp_pckt.dev_id == ctx->my_id) {
            // Match! Copy to buffer and return
            memcpy(buffer, &temp_pckt, bytes);
            *out_len = (size_t)bytes;
            return OK; 
        } else {
            // 3. Mismatch! (Simulating shared bus)
            // Put it back on the queue for someone else
            mq_send(ctx->q_down, (const char*)&temp_pckt, bytes, 0);
            
            // Sleep briefly to yield to other processes
            usleep(1000); 
        }
    }
}

// --- 4. CLIENT PROCESS LOGIC ---
void run_client(int id, mqd_t q_up, mqd_t q_down) {
    device_t dev;
    QueueContext ctx = { .q_up = q_up, .q_down = q_down, .my_id = id };

    io_interface_t io = { 
        .obj = &ctx, 
        .send = cli_mqueue_send, 
        .recv = cli_mqueue_recv 
    };
    
    device_setup(&dev, (dev_id_t)id, io);

    // 1. Prepare Dummy Data (Value = 10 * ID)
    update_t data_array[UPDATE_LEN];
    for(int i=0; i<UPDATE_LEN; i++) data_array[i] = 10 * id; 
    memcpy(dev.data_update, data_array, UPDATE_SIZE);
    
    printf("[CLI %d] Starting... Data Value: %d\n", id, 10*id);

    // 2. Send Update (TX)
    // Small delay to prevent race conditions on startup
    usleep(id * 10000); 
    device_tx(&dev); 
    
    // 3. Receive Result (RX)
    // This will block until Server processes and sends back
    device_rx(&dev);

    // Cleanup
    mq_close(q_up);
    mq_close(q_down);
    exit(0);
}

// --- 5. MAIN ---
int main() {
    // A. Setup Queues
    
    // Uplink: Small messages (Device -> Server)
    struct mq_attr attr_up = {0};
    attr_up.mq_maxmsg = 10;
    attr_up.mq_msgsize = sizeof(dev_pckt_t);
    
    mq_unlink(Q_UPLINK);
    mqd_t mq_up = mq_open(Q_UPLINK, O_CREAT | O_RDWR, 0644, &attr_up);
    if(mq_up == (mqd_t)-1) { perror("open uplink"); exit(1); }

    // Downlink: Large messages (Server -> Device)
    struct mq_attr attr_down = {0};
    attr_down.mq_maxmsg = 10;
    attr_down.mq_msgsize = sizeof(srv_pckt_t); 
    
    mq_unlink(Q_DOWNLINK);
    mqd_t mq_down = mq_open(Q_DOWNLINK, O_CREAT | O_RDWR, 0644, &attr_down);
    if(mq_down == (mqd_t)-1) { perror("open downlink"); exit(1); }

    printf("[SYSTEM] Queues Ready. Up: %ld bytes, Down: %ld bytes\n", 
           attr_up.mq_msgsize, attr_down.mq_msgsize);

    // B. Fork Clients
    for(int i=1; i <= MAX_NUM_CLIENTS; i++) {
        if(fork() == 0) {
            run_client(i, mq_up, mq_down);
        }
    }

    // C. Setup Server
    server_t srv;
    QueueContext ctx = { .q_up = mq_up, .q_down = mq_down, .my_id = 0 };

    io_interface_t srv_io = { 
        .obj = &ctx, 
        .send = srv_mqueue_send, 
        .recv = srv_mqueue_recv 
    };
    
    // Server ID 100
    server_setup(&srv, 100, srv_io);

    // D. Run Server Logic
    printf("\n[MAIN] --- PHASE 1: Server Collection (RX) ---\n");
    // This blocks until MAX_NUM_CLIENTS have sent data
    run_srv_state(&srv); 

    printf("\n[MAIN] --- PHASE 2: Server Aggregation & Distribution (TX) ---\n");
    // This calculates HMACs, Shares, and Broadcasts
    run_srv_state(&srv);

    // E. Wait for children to verify and finish
    printf("\n[MAIN] --- Waiting for clients to finish ---\n");
    while(wait(NULL) > 0);

    // F. Cleanup
    mq_close(mq_up); mq_unlink(Q_UPLINK);
    mq_close(mq_down); mq_unlink(Q_DOWNLINK);

    printf("[MAIN] Test Complete.\n");
    return 0;
}