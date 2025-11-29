#include <mqueue.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#include "common.h"
#include "dev_protocol.h"
#include "puf_data.h"

#define QUEUE_NAME "/puf_test_queue"

prot_ret_t mqueue_send(void* obj, const uint8_t* data, size_t data_len){
    mqd_t* mq_ptr = (mqd_t*)obj;

    if(mq_send(*mq_ptr, (const char*) data, data_len, 0) == -1){
        perror("mq_send");
        return ERROR;
    }
    return OK;
}

prot_ret_t mqueue_recv(void* obj, uint8_t* buffer, size_t max_len, size_t* out_len){
    return OK; //dummy
}

int main(){

    struct mq_attr attr = {0};
    attr.mq_maxmsg = 5;
    attr.mq_msgsize = sizeof(dev_pckt_t);

    mq_unlink(QUEUE_NAME);

    mqd_t mq = mq_open(QUEUE_NAME, O_CREAT | O_RDWR, 0644, &attr);

    if(mq == (mqd_t)-1){
        perror("mq_open");
        exit(1);
    }

    device_t dev;
    io_interface_t io = {
        .obj = &mq,
        .send = mqueue_send,
        .recv = mqueue_recv,
    };

    device_setup(&dev, 1, io);

    printf("\n [MAIN] generating %d sensor values (16-bit)...\n", UPDATE_LEN);

    update_t sensor_values[UPDATE_LEN];

    for(int i = 0; i < UPDATE_LEN; i++){
        sensor_values[i] = 100 + i;
        printf("[%02d] %d", i, sensor_values[i]);
        if((i+1)%5 == 0)
            printf("\n");
    }

    memcpy(dev.data_update, sensor_values, UPDATE_SIZE);

    printf("\n[MAIN] Executing TX...\n");

    device_tx(&dev);

    dev_pckt_t rx_pckt;
    ssize_t bytes = mq_receive(mq, (char*)&rx_pckt, sizeof(dev_pckt_t), NULL);

    if(bytes > 0){
         printf("\n[SERVER] Packet Received.\n");
        
        // HMAC Check
        int hmac_idx = (rx_pckt.current_link + PUF_ITERATIONS) % CHAIN_LEN;
        private_key_t srv_key = (private_key_t)PUF_CHAIN_SRV[hmac_idx];
        private_key_t calc_hmac = calc_hmac_sign(rx_pckt.payload, DEV_PAYLOAD_SIZE, srv_key);
        
        if(calc_hmac == rx_pckt.dev_hmac_sign) {
            printf("[SERVER] HMAC Verified (0x%08X)\n", calc_hmac);
            
            // ---------------------------------------------------------
            // 6. DECODING THE DATA
            // ---------------------------------------------------------
            printf("[SERVER] Decrypting Payload...\n");
            
            // Buffer to hold the de-obfuscated 128-bit blocks
            uint128_t plain_blocks[PUF_ITERATIONS];
            
            puf_chain_t ta_chain = PUF_CHAIN_TA[rx_pckt.dev_id - 1];
            puf_state_t link = rx_pckt.current_link;

            // De-obfuscate loop
            for(int i=0; i<PUF_ITERATIONS; i++) {
                payload_t p = rx_pckt.payload[i];
                payload_t ta = theta_function(ta_chain, link + i);
                payload_t srv = theta_function(PUF_CHAIN_SRV, link + i);
                
                // Inverse Operation: (Payload ^ SRV) - TA
                plain_blocks[i] = (p ^ srv) - ta;
            }

            // Cast the contiguous 128-bit blocks back to 16-bit array
            update_t* decoded_values = (update_t*)plain_blocks;

            printf("--- Decoded Sensor Values ---\n");
            int match_count = 0;
            for(int i=0; i<UPDATE_LEN; i++) {
                printf("[%02d] Value: %d", i, decoded_values[i]);
                
                // Verification
                if(decoded_values[i] == sensor_values[i]) {
                    printf(" (OK)\n");
                    match_count++;
                } else {
                    printf(" (FAIL - Expected %d)\n", sensor_values[i]);
                }
            }
            
            if(match_count == UPDATE_LEN) printf("\n[SUCCESS] All components recovered correctly.\n");
            else printf("\n[FAILURE] Data corruption detected.\n");

        } else {
            printf("[SERVER] HMAC Failed!\n");
        }
    }

    mq_close(mq);
    mq_unlink(QUEUE_NAME);
    return 0;
}