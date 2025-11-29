#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "dev_protocol.h"
#include "common.h"
#include "puf_data.h"

void run_device_state(device_t *dev){
    dev->current_state(dev);
}

void device_rx(device_t* dev){
    #if DEBUG
        printf("[DEVICE %d] Entered RX state\n", dev->dev_id);
    #endif

    srv_pckt_t srv_pckt;
    size_t out_len = 0;

    if(dev->io.recv(dev->io.obj, (uint8_t*)&srv_pckt, sizeof(srv_pckt_t), &out_len) == OK){
        #if DEBUG
        printf("[DEVICE %d] Packet received from server, verifying HMAC\n", dev->dev_id);
        #endif

        uint8_t buffer[sizeof(srv_pckt.aggr_sum) + sizeof(srv_pckt.shares)];

        memcpy(buffer, srv_pckt.aggr_sum, sizeof(srv_pckt.aggr_sum));
        memcpy(buffer + sizeof(srv_pckt.aggr_sum), srv_pckt.shares, sizeof(srv_pckt.shares));

        int hmac_idx = (dev->current_link + PUF_ITERATIONS) % CHAIN_LEN;

        private_key_t srv_key = (private_key_t)PUF_CHAIN_SRV[hmac_idx];

        private_key_t calc_hmac = calc_hmac_sign(buffer, sizeof(buffer), srv_key);

        if(calc_hmac != srv_pckt.srv_hmac_sign){
            #if DEBUG
            printf("[DEVICE %d] HMAC ERROR, expected 0x%08X, received 0x%08X\n", dev->dev_id, calc_hmac, srv_pckt.srv_hmac_sign);
            #endif
            return;
        }

        #if DEBUG
            printf("[DEVICE %d] HMAC VERIFIED, expected 0x%08X, received 0x%08X\n", dev->dev_id, calc_hmac, srv_pckt.srv_hmac_sign);
        #endif

        //the device now has to decrypt the message

        puf_chain_t chain_TA = PUF_CHAIN_TA[dev->dev_id - 1];
        payload_t def_update[PUF_ITERATIONS];

        #if DEBUG
        printf("[DEVICE %d] Update;\n", dev->dev_id);
        #endif

        for(int i = 0; i < PUF_ITERATIONS; i++){
            puf_resp_t dev_link = theta_function(chain_TA, dev->current_link + i);

            payload_t dev_shares = srv_pckt.shares[i];

            def_update[i] = srv_pckt.aggr_sum[i] - dev_shares - dev_link;
        }
        
        update_t *reconstructed_data = (update_t*)def_update;

        char log_buf[256]; 
        int offset = 0;
        offset += snprintf(log_buf + offset, sizeof(log_buf) - offset, "[DEVICE %d] Final Data: [ ", dev->dev_id);

        for(int i = 0; i < UPDATE_LEN; i++){
            offset += snprintf(log_buf + offset, sizeof(log_buf) - offset, "%u ", (unsigned int)reconstructed_data[i]);
        }
        snprintf(log_buf + offset, sizeof(log_buf) - offset, "]\n");
        
        printf("%s", log_buf);
        fflush(stdout);

        dev->current_link = dev->current_link + PUF_ITERATIONS;
        dev->current_state = device_tx;
    }
}

void device_tx(device_t* dev){

    // packet to send
    dev_pckt_t dev_pckt;
    memset(&dev_pckt, 0, sizeof(dev_pckt_t));

    //set metadata
    dev_pckt.dev_id = dev->dev_id;
    dev_pckt.current_link = dev->current_link;

    //get current link in the chain, TA and SRV are synchronized on the same one
    puf_state_t curr_link = (dev->current_link) % CHAIN_LEN;

    puf_chain_t chain_TA = PUF_CHAIN_TA[dev->dev_id - 1];
    puf_chain_t chain_SRV = PUF_CHAIN_SRV;

    #if DEBUG
        printf("[DEVICE %d] TX state, preparing messages\n",  dev->dev_id);
    #endif

    // ZERO PADDING
    uint8_t padded_update[DEV_PAYLOAD_SIZE];
    memset(&padded_update, 0, DEV_PAYLOAD_SIZE);

    //8byte set to zero, the rest is equal to the real update
    memcpy(&padded_update, dev->data_update, UPDATE_SIZE);

    // OBFUSCATION: xOBF = xA + link_TA
    payload_t* obf_update = (payload_t*)padded_update;

    for(int i = 0; i < PUF_ITERATIONS; i++){
        puf_resp_t link_TA = theta_function(chain_TA, curr_link + i);
        puf_resp_t link_SRV = theta_function(chain_SRV, curr_link + i);

        dev_pckt.payload[i] = (obf_update[i] + link_TA) ^ link_SRV;
    }

    // COMPUTE HMAC: HMAX(link_SRV + 1)[xOBF]

    private_key_t dev_hmac_key;
    
    //check if modulo is necessary or not
    int hmac_idx = (dev->current_link + PUF_ITERATIONS) % CHAIN_LEN;

    //use the link_SRV + 1 as key
    dev_hmac_key = (private_key_t)chain_SRV[hmac_idx];

    //compute HMAC
    dev_pckt.dev_hmac_sign = calc_hmac_sign(dev_pckt.payload, DEV_PAYLOAD_SIZE, dev_hmac_key);
    
    // send the packet to the server using callbacks
    #if DEBUG
        printf("[DEVICE %d] Sending packet with HMAC 0x%08X\n", dev_pckt.dev_id, dev_pckt.dev_hmac_sign);
    #endif

    if(dev->io.send(dev->io.obj, (uint8_t*)&dev_pckt, sizeof(dev_pckt_t))){
        #if DEBUG
            printf("[DEVICE %d] packet sent to server\n", dev->dev_id);
        #endif
    } //per la send

    dev->current_state = device_rx;
}


// function to setup the device
void device_setup(device_t* dev, dev_id_t dev_id, io_interface_t io){
    memset(dev, 0, sizeof(device_t));
    dev->dev_id = dev_id;
    dev->io = io;
    dev->current_link = INITIAL_LINK;
    dev->current_state = device_tx;
}


/*
//quando poi uso queste funzioni, devo fare semplicemente un wrapper
prot_ret_t mqueue_send(void* obj, const uint8_t* data, size_t len){
    mqd_t queue = (mqd_t)(intptr_t)obj; //intptr_t to safely cast to integer
    return OK;
}

prot_ret_t mqueue_recv(void* obj, uint8_t* buffer, size_t max_len, size_t* out_len){
    return OK;
}
    */