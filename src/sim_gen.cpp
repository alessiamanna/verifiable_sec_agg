#include "sim_gen.h"
#include "crypto_utils.h"
#include "puf_manager.h"
#include "puf_utils.h"
#include "common_share.h"
#include <random>
#include <algorithm>
#include <cmath>
#include <cstring>

#define CC_SIM_TARGET 0xCCCC

// this function sets the number of neighbors for each node in the recovery topology
// we use the C factor to determine the degree of the graph, as in Bell et al. (CCS 2020, SecAgg+)
int compute_polylog_degree(int num_clients, int threshold, double c_factor) {
    if (num_clients <= 1) return 0;
    if (c_factor <= 0.0) c_factor = DEFAULT_BELL_C_FACTOR;
    int log_deg = static_cast<int>(std::ceil(c_factor * std::log2(static_cast<double>(num_clients))));
    int deg = std::max(threshold, log_deg);
    //degree cannot be higher than num_clients - 1 (complete graph)
    if (deg >= num_clients) {
        deg = num_clients - 1;
    }
    return deg;
}

void configure_polylog_recovery_topology(int num_clients, int degree, uint32_t seed) {
    if (degree <= 0 || num_clients <= 1) {
        configure_complete_recovery_topology(0);
        return;
    }
    if (degree >= num_clients - 1) {
        configure_complete_recovery_topology(num_clients);
        return;
    }

    // Bell et al. (CCS 2020, SecAgg+) randomly permuted (N, k)-Harary graph H_{N, k}:
    // 1. Place vertices around a circle after applying a uniform random permutation `perm`.
    // 2. Connect each vertex `pos` to `r = floor(k / 2)` predecessors and `r` successors.
    // 3. If `k` is odd:
    //    - When `N` is even, connect `pos` to its antipodal vertex `(pos + N/2) % N`
    //      (giving a strictly symmetric undirected k-regular Harary graph).
    //    - When `N` is odd, connect `pos` to `(pos + r + 1) % N` (giving exact degree k).
    std::vector<int> perm(num_clients);
    for (int i = 0; i < num_clients; i++) {
        perm[i] = i;
    }
    std::mt19937 rng(seed);
    std::shuffle(perm.begin(), perm.end(), rng);

    std::vector<node_set_t> topology(MAX_NUM_CLIENTS);
    for (int i = 0; i < MAX_NUM_CLIENTS; i++) {
        topology[i].node_count = 0;
    }

    const int half_deg = degree / 2;
    const bool odd_deg = (degree % 2) != 0;

    for (int pos = 0; pos < num_clients; pos++) {
        node_id_t u = static_cast<node_id_t>(perm[pos]);
        std::vector<node_id_t> neighbors;
        neighbors.reserve(degree);

        for (int step = 1; step <= half_deg; step++) {
            node_id_t succ = static_cast<node_id_t>(perm[(pos + step) % num_clients]);
            node_id_t pred = static_cast<node_id_t>(perm[(pos - step + num_clients) % num_clients]);
            neighbors.push_back(succ);
            neighbors.push_back(pred);
        }

        if (odd_deg) {
            int extra_offset = (num_clients % 2 == 0) ? (num_clients / 2) : (half_deg + 1);
            node_id_t antipodal = static_cast<node_id_t>(perm[(pos + extra_offset) % num_clients]);
            neighbors.push_back(antipodal);
        }

        std::sort(neighbors.begin(), neighbors.end());
        for (node_id_t v : neighbors) {
            node_set_add(&topology[u], v);
        }
    }

    configure_recovery_topology(num_clients, topology.data());
}

// generates a sequnece of random number from 1 to 1000 for each client, used as weights for the model update vector. Same seed will generate the same sequence of weights for each client.
void gen_random_weights(size_t update_len, uint32_t* out_weights, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(1, 1000);
    for (size_t i = 0; i < update_len; i++) {
        out_weights[i] = dist(rng);
    }
}

//generates a matrix of random vector weights, size num_clients x update_len
std::vector<std::vector<uint32_t>> simulate_weights(int num_clients, size_t update_len, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(1, 1000);
    std::vector<std::vector<uint32_t>> client_weights(num_clients, std::vector<uint32_t>(update_len));
    for (int i = 0; i < num_clients; i++) {
        for (size_t j = 0; j < update_len; j++) {
            client_weights[i][j] = dist(rng);
        }
    }
    return client_weights;
}

//randomly simulates dropouts 
std::vector<int> simulate_dropouts(int num_clients, int num_dropouts, node_id_t exclude_node_id, uint32_t seed) {
    std::vector<int> candidates;
    candidates.reserve(num_clients > 0 ? num_clients - 1 : 0);
    for (int i = 0; i < num_clients; i++) {
        if (static_cast<node_id_t>(i) != exclude_node_id) {
            candidates.push_back(i);
        }
    }

    std::mt19937 rng(seed);
    std::shuffle(candidates.begin(), candidates.end(), rng);

    int actual_dropouts = std::min(num_dropouts, static_cast<int>(candidates.size()));
    std::vector<int> dropouts(candidates.begin(), candidates.begin() + actual_dropouts);
    std::sort(dropouts.begin(), dropouts.end());
    return dropouts;
}

bool is_node_dropped(int node_id, const std::vector<int>& dropouts) {
    for (int d : dropouts) {
        if (d == node_id) return true;
    }
    return false;
}

void sim_setup_node_environment(
    int num_clients,
    int threshold,
    int degree,
    node_id_t bench_node_id,
    puf_index_t base_ta_idx,
    sim_cc_context_t* out_cc_ctx
) {
    // 1. Configure sparse polylogarithmic recovery graph (or complete if degree >= N-1)
    configure_polylog_recovery_topology(num_clients, degree, 0x12345678u + static_cast<uint32_t>(num_clients));
   
    server_db_set_threshold(threshold);

    // 2. Generate P-256 consistency check commitments G1, G2 and secret scalars Scc1, Scc2
    ecc_generate_cc(out_cc_ctx->G1, out_cc_ctx->G2, out_cc_ctx->Scc1, out_cc_ctx->Scc2);
    server_db_store_commitments(out_cc_ctx->G1, out_cc_ctx->G2);

    // 3. Create Shamir shares over Z_q and store the blinded CC offset for bench_node_id
    // these are the shares that will be used for the consistency check
    std::vector<ecc_scalar_t> shares_y(MAX_NUM_CLIENTS);
    std::vector<ecc_scalar_t> shares_z(MAX_NUM_CLIENTS);
    ecc_shamir_create_shares(out_cc_ctx->Scc1, num_clients, threshold, shares_y.data());
    ecc_shamir_create_shares(out_cc_ctx->Scc2, num_clients, threshold, shares_z.data());

    // PUF chains
    ta_chains_t chains;
    get_ta_chains(bench_node_id, base_ta_idx, &chains);

    puf_resp_t puf_cc1 = chains.share_chain.share_cc1;
    puf_resp_t puf_cc2 = chains.share_chain.share_cc2;

    //shared key associated to the node
    protocol_key_t k = get_shared_key(bench_node_id, CC_SIM_TARGET);

    uint8_t mask_y[ECC_SCALAR_LEN];
    uint8_t mask_z[ECC_SCALAR_LEN];
    compute_share_h(puf_cc1, k, mask_y, ECC_SCALAR_LEN);
    compute_share_h(puf_cc2, k, mask_z, ECC_SCALAR_LEN);

    uint8_t offset_y[ECC_SCALAR_LEN];
    uint8_t offset_z[ECC_SCALAR_LEN];
    // compute the offset for the bench_node_id by XORing the share with the mask, so the server wont get plaintext shares, but only the offset which given back to the node enables it to query it's puf and get back the share
    for (size_t j = 0; j < ECC_SCALAR_LEN; j++) {
        offset_y[j] = shares_y[bench_node_id][j] ^ mask_y[j];
        offset_z[j] = shares_z[bench_node_id][j] ^ mask_z[j];
    }

    server_db_store_offset_cc(bench_node_id, offset_y, offset_z);
}
//these are all the simulated functions that generate valid messages for the server to send to the clients for each phase of the protocol
void gen_valid_dropout_list(
    int num_clients,
    int num_dropouts,
    node_id_t bench_node_id,
    srv_id_t srv_id,
    puf_index_t srv_link,
    uint32_t seed,
    srv_dropout_list_t* out_msg,
    node_set_t* out_dropouts
) {
    out_dropouts->node_count = 0;
    std::vector<int> dropped_ids = simulate_dropouts(num_clients, num_dropouts, bench_node_id, seed);
    for (int id : dropped_ids) {
        node_set_add(out_dropouts, static_cast<node_id_t>(id));
    }

    out_msg->type = MSG_SRV_SEND_DROP_LIST;
    out_msg->srv_id = srv_id;
    out_msg->n_3 = *out_dropouts;

    transport_chain_t srv_chain;
    get_transport_chain(srv_link, &srv_chain);
    sign_node_set(out_dropouts, srv_chain.l_3_hmac_drop, out_msg->n_4);
}

void gen_valid_cc_result(
    srv_id_t srv_id,
    const sim_cc_context_t* cc_ctx,
    const srv_dropout_list_t* drop_msg,
    srv_cc_result_t* out_msg
) {
    uint8_t h[SHA256_DIGEST];
    node_set_t local_z_set = drop_msg->n_3;
    hash_node_set_sha256(&local_z_set, h);

    out_msg->type = MSG_SRV_SEND_CC_RESULT;
    out_msg->srv_id = srv_id;
    ecc_scalar_mul_add_mod(h, cc_ctx->Scc1, cc_ctx->Scc2, out_msg->W);
}

void gen_valid_global_update(
    srv_id_t srv_id,
    uint32_t num_participants,
    size_t update_len,
    puf_index_t srv_link,
    uint32_t seed,
    srv_global_update_t* out_msg
) {
    transport_chain_t srv_chain;
    get_transport_chain(srv_link, &srv_chain);

    out_msg->type = MSG_SRV_SEND_GLOBAL_UPDATE;
    out_msg->srv_id = srv_id;
    out_msg->num_participants = num_participants;
    out_msg->len = static_cast<uint32_t>(update_len);
    out_msg->n_7.resize(update_len);
    out_msg->n_8.resize(update_len);

    std::mt19937 rng(seed);
    std::uniform_int_distribution<uint32_t> dist(1, 10000);
    const update_t b_term = UInt128::from_uint32(num_participants * VERIF_B);

    for (size_t i = 0; i < update_len; i++) {
        update_t x_sum = UInt128::from_uint32(dist(rng));
        update_t x_verif = (x_sum * VERIF_A) + b_term;
        out_msg->n_7[i] = encrypt_puf(x_sum, srv_chain.l_5_final_data);
        out_msg->n_8[i] = encrypt_puf(x_verif, srv_chain.l_6_final_verif);
    }

    sign_payload(out_msg->n_7.data(), out_msg->n_8.data(), update_len, srv_chain.l_7_global, out_msg->n_9);
}
