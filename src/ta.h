#ifndef TA_H
#define TA_H

#include "common.h"
#include "common_share.h"
#include "puf_data.h"
#include "server.h"

void secret_padding(uint8_t* padded_secret, puf_resp_t secret);
protocol_key_t simulated_key(node_id_t node_helper, node_id_t node_target);
void ta_compute_offset(int N, int K, puf_index_t base_idx);
void ta_compute_cc_offset(int N, int K, puf_index_t base_idx);
void ta_send_global_masks(server_t* srv, int N, puf_index_t base_idx);

#endif