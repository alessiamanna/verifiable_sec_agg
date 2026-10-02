#ifndef SIM_GEN_H
#define SIM_GEN_H

#include <vector>
#include <cstdint>
#include <cstddef>
#include "heversa_api.h"

/**
 * Holds the Trusted Authority's secret consistency-check scalars (Scc1, Scc2)
 * and public commitments (G1, G2) so the benchmark harness can synthesize
 * cryptographically valid server consistency-check responses (W = h*Scc1 + Scc2)
 * for any simulated dropout set without running all N nodes.
 */
struct sim_cc_context_t {
    ecc_point_t G1;
    ecc_point_t G2;
    ecc_scalar_t Scc1;
    ecc_scalar_t Scc2;
};

/**
 * Default scaling factor c for Bell et al. (CCS 2020, SecAgg+) Harary graph degree:
 *   k = ceil(c * log2(N))
 * Derived from the hypergeometric tail bound for joint dropout (delta) and corruption (gamma)
 * resilience, and yields strictly increasing concave degrees across N = 50..500 (step 50):
 *   k = 34, 40, 44, 46, 48, 50, 51, 52, 53, 54.
 */
constexpr double DEFAULT_BELL_C_FACTOR = 6.0;

/**
 * Compute Bell et al. (SecAgg+) logarithmic recovery neighborhood degree:
 *   k = min(N - 1, max(threshold, ceil(c_factor * log2(num_clients))))
 */
int compute_polylog_degree(int num_clients, int threshold = 0, double c_factor = DEFAULT_BELL_C_FACTOR);

/**
 * Configure a randomly permuted (N, k)-Harary graph topology (Bell et al., CCS 2020)
 * where every node has exact degree `degree` (|K_j| = degree = ceil(c * log2(N))).
 */
void configure_polylog_recovery_topology(int num_clients, int degree, uint32_t seed = 42);

/**
 * Generate random uint32_t model weights for a single node.
 */
void gen_random_weights(size_t update_len, uint32_t* out_weights, uint32_t seed);

/**
 * Generate random uint32_t model weights for multiple simulated clients.
 */
std::vector<std::vector<uint32_t>> simulate_weights(int num_clients, size_t update_len, uint32_t seed = 42);

/**
 * Generate a list of dropped node IDs (excluding the benchmarked node itself).
 */
std::vector<int> simulate_dropouts(int num_clients, int num_dropouts, node_id_t exclude_node_id = 0, uint32_t seed = 1337);

/**
 * Check if a node ID is present in the dropout vector.
 */
bool is_node_dropped(int node_id, const std::vector<int>& dropouts);

/**
 * Set up the Trusted Authority / Server DB state required by a single benchmarked node
 * (sparse polylogarithmic recovery topology of degree `degree`, ECC commitments G1/G2,
 * and blinded CC share offsets for bench_node_id).
 */
void sim_setup_node_environment(
    int num_clients,
    int threshold,
    int degree,
    node_id_t bench_node_id,
    puf_index_t base_ta_idx,
    sim_cc_context_t* out_cc_ctx
);

/**
 * Build a structurally and cryptographically valid srv_dropout_list_t message
 * (signed with the server's PUF transport key l_3_hmac_drop at srv_link)
 * containing num_dropouts randomly chosen peers.
 */
void gen_valid_dropout_list(
    int num_clients,
    int num_dropouts,
    node_id_t bench_node_id,
    srv_id_t srv_id,
    puf_index_t srv_link,
    uint32_t seed,
    srv_dropout_list_t* out_msg,
    node_set_t* out_dropouts
);

/**
 * Synthesize a cryptographically valid srv_cc_result_t message (W = h*Scc1 + Scc2 mod q)
 * for the given dropout list message so that client_verify_cc_result() executes the full
 * P-256 point verification and succeeds.
 */
void gen_valid_cc_result(
    srv_id_t srv_id,
    const sim_cc_context_t* cc_ctx,
    const srv_dropout_list_t* drop_msg,
    srv_cc_result_t* out_msg
);

/**
 * Synthesize a cryptographically valid srv_global_update_t message (n_7, n_8, n_9)
 * encrypted with l_5_final_data and l_6_final_verif and signed with l_7_global at srv_link,
 * satisfying x_hat_sum[i] = x_sum[i] * VERIF_A + num_participants * VERIF_B.
 */
void gen_valid_global_update(
    srv_id_t srv_id,
    uint32_t num_participants,
    size_t update_len,
    puf_index_t srv_link,
    uint32_t seed,
    srv_global_update_t* out_msg
);

#endif // SIM_GEN_H
