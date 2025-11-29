#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "srv_protocol.h"
#include "common.h"
#include "puf_data.h"

void generate_shares(server_t* srv, shares_t shares_out[MAX_NUM_CLIENTS][PUF_ITERATIONS]){

    payload_t cum_sum[PUF_ITERATIONS] = {0};

    for(int i = 0; i < MAX_NUM_CLIENTS; i++){
        if(srv->rcvd_updates[i] == 1){
            puf_chain_t chain = PUF_CHAIN_TA[i];
            for(int k = 0; k < PUF_ITERATIONS; k++){
                cum_sum[k] += theta_function(chain, srv->current_link + k);
            }
        }
    }

    for(int i = 0; i  < MAX_NUM_CLIENTS; i++){
        if(srv->rcvd_updates[i]){
            puf_chain_t chain_ta = PUF_CHAIN_TA[i];
            for(int k = 0; k < PUF_ITERATIONS; k++){
                puf_resp_t dev_mask = theta_function(chain_ta, srv->current_link + k);

                shares_out[i][k] = cum_sum[k] - dev_mask;
            }
        }
    }
}
void process_data(server_t *srv, dev_pckt_t *rx_pckt){

    //now we have to retrive the obfuscated update

    puf_state_t curr_link = srv->current_link;

    for(int i = 0; i < PUF_ITERATIONS; i++){
        puf_resp_t link_SRV = theta_function(PUF_CHAIN_SRV, curr_link + i);
        payload_t obf_cumsum = (rx_pckt->payload[i] ^ link_SRV);

        srv->cumsum[i] = srv->cumsum[i] + obf_cumsum;
    }

    srv->rcvd_updates[rx_pckt->dev_id - 1] = 1; //mark dev's update as received
    srv->num_devs += 1;

    #if DEBUG
        printf("[SERVER] Processed Device %d.\n", rx_pckt->dev_id);
    #endif
}

void run_srv_state(server_t *srv){
    srv->current_state(srv);
}

//states

void server_rx(server_t* srv){

    // UPDATE RETRIEVAL
    // 1. check if received HMAC == calc HMAC
    // 2. retrieve obfuscated update Xsum = m0 xor link_S

    #if DEBUG
        printf("[SERVER %d] Processing Updates\n", srv->srv_id);
    #endif

    memset(srv->ta_sum, 0, sizeof(srv->ta_sum));
    memset(srv->cumsum, 0, sizeof(srv->cumsum));
    srv->num_devs = 0;
    memset(srv->rcvd_updates, 0, sizeof(srv->rcvd_updates));

    while(srv->num_devs < MAX_NUM_CLIENTS){

        dev_pckt_t rx_pckt;
        memset(&rx_pckt, 0, sizeof(dev_pckt_t));

        size_t out_len = 0;

        if(srv->io.recv(srv->io.obj, (uint8_t*)&rx_pckt, sizeof(dev_pckt_t), &out_len) == OK){
            
            //only for debug purposes, synchronization should depend on PHEMAP?
            if(rx_pckt.current_link != srv->current_link){
                #if DEBUG
                    printf("[SERVER] Warning: Device %d Link Mismatch (Pckt: %d, Srv: %d)\n", rx_pckt.dev_id, rx_pckt.current_link, srv->current_link);
                #endif
                continue;
            }

            //check HMAC
            int hmac_idx = (srv->current_link + PUF_ITERATIONS) % CHAIN_LEN;

            private_key_t srv_key = (private_key_t)PUF_CHAIN_SRV[hmac_idx];
            private_key_t calc_hmac = calc_hmac_sign(rx_pckt.payload, DEV_PAYLOAD_SIZE, srv_key);

            if(calc_hmac != rx_pckt.dev_hmac_sign){
                #if DEBUG
                    printf("[SERVER] HMAC Mismatch! Rcvd 0x%08X, expected 0x%08X. Discarding.\n", rx_pckt.dev_hmac_sign, calc_hmac);
                #endif

                return;
            } else{
                #if DEBUG
                    printf("[SERVER] HMAC calculated! Rcvd 0x%08X, expected 0x%08X.\n", rx_pckt.dev_hmac_sign, calc_hmac);
                #endif
                process_data(srv, &rx_pckt);
            }
        }
    }
    srv->current_state = server_tx;
}

void server_tx(server_t* srv){

    shares_t dev_shares[MAX_NUM_CLIENTS][PUF_ITERATIONS];

    generate_shares(srv, dev_shares);

    #if DEBUG
        printf("[SERVER] Trasmitting group obfuscated sum and shares\n");
    #endif

    for(int i = 1; i <= MAX_NUM_CLIENTS; i++){

        if(srv->rcvd_updates[i-1] == 0) continue;
        srv_pckt_t srv_pckt;
        memset(&srv_pckt, 0, sizeof(srv_pckt));

        // METADATA
        srv_pckt.srv_id = srv->srv_id;
        srv_pckt.current_link = srv->current_link;
        srv_pckt.dev_id = (dev_id_t)i;

        puf_chain_t dst_ta_chain = PUF_CHAIN_TA[i-1];

        //the trusted authority should send these. 
        for(int k = 0; k < PUF_ITERATIONS; k++){
            srv_pckt.aggr_sum[k] = srv->cumsum[k];
            srv_pckt.shares[k] = dev_shares[i-1][k];
        }

        //HMAC

        uint8_t buffer[sizeof(srv_pckt.aggr_sum) + sizeof(srv_pckt.shares)];

        memcpy(buffer, srv_pckt.aggr_sum, sizeof(srv_pckt.aggr_sum));

        memcpy(buffer + sizeof(srv_pckt.aggr_sum), srv_pckt.shares, sizeof(srv_pckt.shares));

        int hmac_idx = (srv->current_link + PUF_ITERATIONS) % CHAIN_LEN;
        private_key_t srv_key = (private_key_t)PUF_CHAIN_SRV[hmac_idx];

        srv_pckt.srv_hmac_sign = calc_hmac_sign(buffer, sizeof(buffer), srv_key);

        #if DEBUG
        printf("[SERVER] Calculated HMAC for device %d, 0x%08X\n", srv_pckt.dev_id, srv_pckt.srv_hmac_sign);
        #endif

        if(srv->io.send(srv->io.obj, (uint8_t*)&srv_pckt, sizeof(srv_pckt_t)) == OK){
            #if DEBUG
            printf("[SERVER] Sending packet\n");
            #endif
        }

    }
    srv->current_link = srv->current_link + PUF_ITERATIONS;
    srv->current_state = server_rx;
}

void server_setup(server_t* srv, srv_id_t srv_id, io_interface_t io){
    memset(srv, 0, sizeof(server_t));
    srv->srv_id = srv_id;
    srv->io = io;
    srv->current_state = server_rx;
    srv->current_link = INITIAL_LINK;
}