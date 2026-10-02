#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <ctime>
#include <vector>
#include <string>
#include <algorithm>
#include <numeric>
#include <memory>

#include "heversa_api.h"
#include "crypto_utils.h"
#include "puf_manager.h"
#include "sim_gen.h"

#ifdef BENCHMARK_RUNTIME_PUF
#include "bench/puf_data.h"
#endif

#if defined(__linux__)
#include <sched.h>
#include <pthread.h>
static void pin_thread_and_boost_priority() {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}
#else
static void pin_thread_and_boost_priority() {}
#endif

// ============================================================================
// Cache Strategy (Option C): Working-set pollution between iterations
// Ultra96-V2 (Zynq UltraScale+ ZU3EG, quad Cortex-A53):
//   L1 D-cache: 32 KB per core (64-byte line size)
//   L2 cache:   1 MB shared (16-way set-associative, 64-byte line size)
// Touching a 2 MB buffer (> 2x L2 size) with a 64-byte stride evicts the
// previous round's working set without privileged cache maintenance ops.
// ============================================================================
static constexpr size_t POLLUTER_SIZE = 2 * 1024 * 1024; // 2 MB
static constexpr size_t CACHE_LINE_SIZE = 64;
static volatile uint8_t g_cache_polluter[POLLUTER_SIZE];

static void pollute_cache(uint32_t round_salt) {
    uint8_t salt = static_cast<uint8_t>(round_salt & 0xFF);
    for (size_t i = 0; i < POLLUTER_SIZE; i += CACHE_LINE_SIZE) {
        g_cache_polluter[i] = static_cast<uint8_t>((i >> 6) ^ salt);
    }
    volatile uint8_t sink = 0;
    for (size_t i = 0; i < POLLUTER_SIZE; i += CACHE_LINE_SIZE) {
        sink ^= g_cache_polluter[i];
    }
    (void)sink;
}

// ============================================================================
// High-Resolution Monotonic Timer
// ============================================================================
static inline uint64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

static inline double ns_to_us(uint64_t ns) {
    return static_cast<double>(ns) / 1000.0;
}

// ============================================================================
// Statistics Calculation
// ============================================================================
struct PhaseStats {
    double min_us;
    double max_us;
    double mean_us;
    double median_us;
    double stdev_us;
};

static PhaseStats compute_stats(const std::vector<double>& samples) {
    PhaseStats s{0.0, 0.0, 0.0, 0.0, 0.0};
    if (samples.empty()) return s;

    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());

    size_t n = sorted.size();
    s.min_us = sorted.front();
    s.max_us = sorted.back();

    double sum = std::accumulate(sorted.begin(), sorted.end(), 0.0);
    s.mean_us = sum / static_cast<double>(n);

    if (n % 2 == 1) {
        s.median_us = sorted[n / 2];
    } else {
        s.median_us = 0.5 * (sorted[n / 2 - 1] + sorted[n / 2]);
    }

    if (n > 1) {
        double sq_diff_sum = 0.0;
        for (double v : sorted) {
            double d = v - s.mean_us;
            sq_diff_sum += d * d;
        }
        s.stdev_us = std::sqrt(sq_diff_sum / static_cast<double>(n - 1));
    }
    return s;
}

// ============================================================================
// Benchmark Configuration
// ============================================================================
enum class TopologyMode {
    LOG2,       // degree = ceil(c * log2(N)) (Bell et al. SecAgg+ Harary graph)
    LOG2_SQ,    // degree = ceil(log2(N)^2)
    COMPLETE    // degree = N - 1 (complete graph)
};

struct BenchConfig {
    std::vector<size_t> update_lens = {1024}; // One or more model update lengths (M)
    int min_clients = 50;                     // Start of client sweep
    int max_clients = 500;                    // End of client sweep
    int step_clients = 50;                    // Step size for client sweep
    int iterations = 30;                      // Protocol iterations per configuration
    TopologyMode topology = TopologyMode::LOG2; // Default Bell et al. Harary recovery topology
    double c_factor = DEFAULT_BELL_C_FACTOR;    // Scaling factor c in k = ceil(c * log2(N))
    int fixed_degree = 0;                     // 0 = auto from topology mode
    int fixed_threshold = 0;                  // 0 = auto (floor(degree * ratio) + 1)
    double threshold_ratio = 0.5;             // Honest majority of recovery neighborhood
    int num_dropouts = 0;                     // Configurable fixed number of dropouts (default 0)
    std::vector<double> dropout_ratios;       // Optional one or more dropout fractions in [0,1)
    bool pollute = true;                      // Option C cache pollution enabled by default
    std::string raw_csv_path = "benchmark_raw.csv";
    std::string summary_csv_path = "benchmark_summary.csv";
};

static std::vector<size_t> parse_size_list(const char* str) {
    std::vector<size_t> out;
    const char* p = str;
    while (*p) {
        char* end = nullptr;
        unsigned long val = std::strtoul(p, &end, 10);
        if (end == p) break;
        out.push_back(static_cast<size_t>(val));
        p = end;
        while (*p == ',' || *p == ' ') p++;
    }
    return out;
}

static std::vector<double> parse_double_list(const char* str, double scale = 1.0) {
    std::vector<double> out;
    const char* p = str;
    while (*p) {
        char* end = nullptr;
        double val = std::strtod(p, &end);
        if (end == p) break;
        out.push_back(val * scale);
        p = end;
        while (*p == ',' || *p == ' ' || *p == '%') p++;
    }
    return out;
}

static void print_usage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  --update-len <M[,M2..]>   Model update vector length(s), e.g. 256 or 16,32,64,128,256,1024 (default: 1024)\n");
    printf("  --min-clients <N>         Minimum number of clients in sweep (default: 50)\n");
    printf("  --max-clients <N>         Maximum number of clients in sweep (default: 500)\n");
    printf("  --step-clients <S>        Step size for client sweep (default: 50)\n");
    printf("  --clients <N>             Run for a single client count N (sets min=max=N)\n");
    printf("  --iterations <I>          Iterations per configuration (default: 30)\n");
    printf("  --topology <mode>         Recovery graph topology: log2 | log2_sq | complete (default: log2)\n");
    printf("  --c-factor <C>            Bell et al. scaling factor c in ceil(c * log2(N)) (default: %.1f)\n", DEFAULT_BELL_C_FACTOR);
    printf("  --degree <D>              Fixed helper degree |K_j| (overrides --topology)\n");
    printf("  --threshold <K>           Fixed Shamir threshold K (default: auto = degree/2 + 1)\n");
    printf("  --threshold-ratio <R>     Threshold ratio R in (0,1] of degree (default: 0.5 -> degree/2 + 1)\n");
    printf("  --dropouts <D>            Fixed number of dropped clients (default: 0)\n");
    printf("  --dropout-pct <P[,P2..]>  Dropout percentage(s) in [0,100), e.g. 10 or 0,10,20,30 (overrides --dropouts)\n");
    printf("  --dropout-ratio <R[,R2]>  Fraction(s) of dropped clients in [0,1), e.g. 0.1 or 0,0.1,0.2,0.3\n");
    printf("  --no-pollute              Disable inter-round cache pollution\n");
    printf("  --raw-csv <path>          Output path for per-iteration CSV (default: benchmark_raw.csv)\n");
    printf("  --summary-csv <path>      Output path for summary stats CSV (default: benchmark_summary.csv)\n");
    printf("  --help                    Show this help message\n");
}

static bool parse_args(int argc, char* argv[], BenchConfig* cfg) {
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--update-len") == 0 && i + 1 < argc) {
            cfg->update_lens = parse_size_list(argv[++i]);
        } else if (std::strcmp(argv[i], "--min-clients") == 0 && i + 1 < argc) {
            cfg->min_clients = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--max-clients") == 0 && i + 1 < argc) {
            cfg->max_clients = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--step-clients") == 0 && i + 1 < argc) {
            cfg->step_clients = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--clients") == 0 && i + 1 < argc) {
            int n = std::atoi(argv[++i]);
            cfg->min_clients = n;
            cfg->max_clients = n;
            cfg->step_clients = 1;
        } else if (std::strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            cfg->iterations = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--topology") == 0 && i + 1 < argc) {
            const char* mode = argv[++i];
            if (std::strcmp(mode, "log2") == 0) {
                cfg->topology = TopologyMode::LOG2;
            } else if (std::strcmp(mode, "log2_sq") == 0) {
                cfg->topology = TopologyMode::LOG2_SQ;
            } else if (std::strcmp(mode, "complete") == 0) {
                cfg->topology = TopologyMode::COMPLETE;
            } else {
                fprintf(stderr, "[ERROR] Unknown topology mode '%s' (use log2, log2_sq, or complete)\n", mode);
                return false;
            }
        } else if (std::strcmp(argv[i], "--c-factor") == 0 && i + 1 < argc) {
            cfg->c_factor = std::atof(argv[++i]);
        } else if (std::strcmp(argv[i], "--degree") == 0 && i + 1 < argc) {
            cfg->fixed_degree = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
            cfg->fixed_threshold = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--threshold-ratio") == 0 && i + 1 < argc) {
            cfg->threshold_ratio = std::atof(argv[++i]);
        } else if (std::strcmp(argv[i], "--dropouts") == 0 && i + 1 < argc) {
            cfg->num_dropouts = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--dropout-pct") == 0 && i + 1 < argc) {
            cfg->dropout_ratios = parse_double_list(argv[++i], 0.01);
        } else if (std::strcmp(argv[i], "--dropout-ratio") == 0 && i + 1 < argc) {
            cfg->dropout_ratios = parse_double_list(argv[++i], 1.0);
        } else if (std::strcmp(argv[i], "--no-pollute") == 0) {
            cfg->pollute = false;
        } else if (std::strcmp(argv[i], "--raw-csv") == 0 && i + 1 < argc) {
            cfg->raw_csv_path = argv[++i];
        } else if (std::strcmp(argv[i], "--summary-csv") == 0 && i + 1 < argc) {
            cfg->summary_csv_path = argv[++i];
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return false;
        } else {
            fprintf(stderr, "[ERROR] Unknown or incomplete argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return false;
        }
    }
    return true;
}

static int select_degree(const BenchConfig& cfg, int num_clients) {
    int deg = 0;
    if (cfg.fixed_degree > 0) {
        deg = cfg.fixed_degree;
    } else if (cfg.topology == TopologyMode::COMPLETE) {
        deg = num_clients - 1;
    } else if (cfg.topology == TopologyMode::LOG2_SQ) {
        double lg = std::log2(static_cast<double>(num_clients));
        deg = static_cast<int>(std::ceil(lg * lg));
    } else {
        deg = compute_polylog_degree(num_clients, 0, cfg.c_factor);
    }
    if (deg < 2) deg = 2;
    if (deg >= num_clients) deg = num_clients - 1;
    return deg;
}

// ============================================================================
// Main Benchmark Runner
// ============================================================================
int main(int argc, char* argv[]) {
    BenchConfig cfg;
    if (!parse_args(argc, argv, &cfg)) {
        return 1;
    }

    pin_thread_and_boost_priority();

    if (cfg.max_clients > MAX_NUM_CLIENTS) {
        fprintf(stderr,
                "[ERROR] Requested max_clients (%d) exceeds compiled MAX_NUM_CLIENTS (%d).\n"
                "Recompile with -DMAX_NUM_CLIENTS=%d.\n",
                cfg.max_clients, MAX_NUM_CLIENTS, cfg.max_clients);
        return 1;
    }
    if (cfg.min_clients < 2 || cfg.min_clients > cfg.max_clients || cfg.step_clients <= 0) {
        fprintf(stderr, "[ERROR] Invalid client sweep range: min=%d, max=%d, step=%d\n",
                cfg.min_clients, cfg.max_clients, cfg.step_clients);
        return 1;
    }
    if (cfg.iterations <= 0 || cfg.update_lens.empty()) {
        fprintf(stderr, "[ERROR] iterations (%d) and update_len must be > 0\n", cfg.iterations);
        return 1;
    }
    size_t max_update_len = 0;
    for (size_t m : cfg.update_lens) {
        if (m == 0) {
            fprintf(stderr, "[ERROR] update_len must be > 0\n");
            return 1;
        }
        if (m > max_update_len) max_update_len = m;
    }

    std::vector<double> active_dropout_ratios = cfg.dropout_ratios;
    if (active_dropout_ratios.empty()) {
        active_dropout_ratios.push_back(-1.0); // Sentinel: use fixed cfg.num_dropouts
    }

#ifdef BENCHMARK_RUNTIME_PUF
    init_puf_chains_bench(0xCAFEBABEu);
#endif

    FILE* raw_csv = std::fopen(cfg.raw_csv_path.c_str(), "w");
    if (!raw_csv) {
        fprintf(stderr, "[ERROR] Cannot open %s for writing\n", cfg.raw_csv_path.c_str());
        return 1;
    }

    FILE* sum_csv = std::fopen(cfg.summary_csv_path.c_str(), "w");
    if (!sum_csv) {
        fprintf(stderr, "[ERROR] Cannot open %s for writing\n", cfg.summary_csv_path.c_str());
        std::fclose(raw_csv);
        return 1;
    }

    // Write CSV headers
    std::fprintf(raw_csv,
        "num_clients,degree,update_len,threshold,num_dropouts,dropout_pct,iteration,"
        "setup_us,phase1_mask_us,phase2_cc_value_us,phase3_cc_verify_us,phase4_shares_us,phase5_final_verif_us,total_node_us\n");

    std::fprintf(sum_csv,
        "num_clients,degree,update_len,threshold,num_dropouts,dropout_pct,iterations,"
        "setup_mean_us,setup_stdev_us,"
        "phase1_mean_us,phase1_stdev_us,phase1_median_us,phase1_min_us,phase1_max_us,"
        "phase2_mean_us,phase2_stdev_us,phase2_median_us,phase2_min_us,phase2_max_us,"
        "phase3_mean_us,phase3_stdev_us,phase3_median_us,phase3_min_us,phase3_max_us,"
        "phase4_mean_us,phase4_stdev_us,phase4_median_us,phase4_min_us,phase4_max_us,"
        "phase5_mean_us,phase5_stdev_us,phase5_median_us,phase5_min_us,phase5_max_us,"
        "total_mean_us,total_stdev_us,total_median_us,total_min_us,total_max_us\n");

    char topo_buf[128];
    if (cfg.topology == TopologyMode::LOG2) {
        std::snprintf(topo_buf, sizeof(topo_buf),
                      "Bell et al. Harary graph: degree = ceil(%.1f * log2(N))", cfg.c_factor);
    } else if (cfg.topology == TopologyMode::LOG2_SQ) {
        std::snprintf(topo_buf, sizeof(topo_buf),
                      "Polylogarithmic Harary graph: degree = ceil(log2(N)^2)");
    } else {
        std::snprintf(topo_buf, sizeof(topo_buf),
                      "Complete graph: degree = N - 1");
    }

    std::string m_list_str;
    for (size_t idx = 0; idx < cfg.update_lens.size(); idx++) {
        if (idx > 0) m_list_str += ", ";
        m_list_str += std::to_string(cfg.update_lens[idx]);
    }

    std::string drop_list_str;
    if (cfg.dropout_ratios.empty()) {
        drop_list_str = std::to_string(cfg.num_dropouts) + " clients (fixed)";
    } else {
        for (size_t idx = 0; idx < cfg.dropout_ratios.size(); idx++) {
            if (idx > 0) drop_list_str += ", ";
            char dbuf[32];
            std::snprintf(dbuf, sizeof(dbuf), "%.1f%%", cfg.dropout_ratios[idx] * 100.0);
            drop_list_str += dbuf;
        }
    }

    printf("====================================================================================================================================\n");
    printf("  HeVerSa Single-Node Benchmark (Avnet Ultra96-V2 Target)\n");
    printf("====================================================================================================================================\n");
    printf("  Update Length (M) : %s\n", m_list_str.c_str());
    printf("  Clients Sweep (N) : %d .. %d (step %d) [MAX_NUM_CLIENTS=%d]\n",
           cfg.min_clients, cfg.max_clients, cfg.step_clients, MAX_NUM_CLIENTS);
    printf("  Dropout Setting   : %s\n", drop_list_str.c_str());
    printf("  Recovery Topology : %s\n", topo_buf);
    printf("  Iterations / Pt   : %d\n", cfg.iterations);
    printf("  Cache Strategy    : %s\n",
           cfg.pollute ? "Option C (2 MB working-set pollution between iterations)" : "Hot cache (no pollution)");
    printf("  Raw CSV Output    : %s\n", cfg.raw_csv_path.c_str());
    printf("  Summary CSV Output: %s\n", cfg.summary_csv_path.c_str());
    printf("====================================================================================================================================\n\n");

    printf("%-5s %-6s %-5s %-4s %-11s | %-9s | %-17s | %-15s | %-17s | %-20s | %-17s | %-20s\n",
           "N", "M", "|K_j|", "K", "Drop",
           "Setup(us)",
           "P1: Mask (us)",
           "P2: CCVal (us)",
           "P3: CCVer (us)",
           "P4: Shares (us)",
           "P5: FinalVer(us)",
           "Total Node (us)");
    printf("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    const node_id_t bench_node_id = 0;
    const srv_id_t srv_id = 99;

    // Pre-allocate reusable message buffers ONCE outside the sweep so no heap
    // allocation/deallocation or OS page fault occurs during timed phases.
    std::vector<uint32_t> weights(max_update_len, 1);
    std::vector<update_t> shared_data_update(max_update_len, UInt128{0, 0, 0, 0});
    auto update_msg = std::make_unique<node_local_update_t>();
    update_msg->n_0.assign(max_update_len, UInt128{0, 0, 0, 0});
    update_msg->n_1.assign(max_update_len, UInt128{0, 0, 0, 0});

    auto drop_msg = std::make_unique<srv_dropout_list_t>();
    auto shares_msg = std::make_unique<node_shares_msg_t>();
    auto global_msg = std::make_unique<srv_global_update_t>();
    global_msg->n_7.assign(max_update_len, UInt128{0, 0, 0, 0});
    global_msg->n_8.assign(max_update_len, UInt128{0, 0, 0, 0});

    int max_possible_degree = select_degree(cfg, cfg.max_clients);
    for (int i = 0; i < max_possible_degree && i < MAX_SHARES; i++) {
        shares_msg->items[i].share_data.assign(sss_SHARE_LEN, 0);
        shares_msg->items[i].share_verif.assign(sss_SHARE_LEN, 0);
    }

    // Warm up OpenSSL thread-local ECC context and node thread-local scratch buffers once
    {
        ecc_point_t dummy_G1, dummy_G2;
        ecc_scalar_t dummy_s1, dummy_s2;
        ecc_generate_cc(dummy_G1, dummy_G2, dummy_s1, dummy_s2);

        sim_cc_context_t warmup_cc;
        sim_setup_node_environment(cfg.min_clients, 2, 2, bench_node_id, INITIAL_LINK, &warmup_cc);
        node_t warmup_node;
        client_setup(&warmup_node, bench_node_id, max_update_len);
        client_mask_update(&warmup_node, weights.data(), max_update_len, update_msg.get());
        gen_valid_global_update(srv_id, static_cast<uint32_t>(cfg.min_clients), max_update_len,
                                warmup_node.current_link_srv, 12345u, global_msg.get());
        client_verify_global_update(&warmup_node, global_msg.get());
    }

    struct ClientSweepPoint {
        int num_clients;
        size_t update_len;
        int degree;
        int threshold;
        int num_dropouts;
        double dropout_pct;
        sim_cc_context_t cc_ctx;
        node_t bench_node;
        double setup_once_us;
        std::vector<double> p1_samples;
        std::vector<double> p2_samples;
        std::vector<double> p3_samples;
        std::vector<double> p4_samples;
        std::vector<double> p5_samples;
        std::vector<double> total_samples;
    };

    std::vector<ClientSweepPoint> sweep_points;
    for (size_t u_len : cfg.update_lens) {
        for (double d_ratio : active_dropout_ratios) {
            for (int num_clients = cfg.min_clients; num_clients <= cfg.max_clients; num_clients += cfg.step_clients) {
                ClientSweepPoint pt{};
                pt.num_clients = num_clients;
                pt.update_len = u_len;
                pt.degree = select_degree(cfg, num_clients);
                pt.threshold = cfg.fixed_threshold > 0
                    ? cfg.fixed_threshold
                    : (static_cast<int>(std::floor(cfg.threshold_ratio * pt.degree)) + 1);
                if (pt.threshold < 2) pt.threshold = 2;
                if (pt.threshold > pt.degree) pt.threshold = pt.degree;

                pt.num_dropouts = d_ratio >= 0.0
                    ? static_cast<int>(std::round(d_ratio * num_clients))
                    : cfg.num_dropouts;
                int max_allowed_dropouts = num_clients - pt.threshold;
                if (pt.num_dropouts > max_allowed_dropouts) {
                    pt.num_dropouts = std::max(0, max_allowed_dropouts);
                }
                pt.dropout_pct = (d_ratio >= 0.0)
                    ? (d_ratio * 100.0)
                    : (100.0 * static_cast<double>(pt.num_dropouts) / static_cast<double>(num_clients));

                pt.p1_samples.reserve(cfg.iterations);
                pt.p2_samples.reserve(cfg.iterations);
                pt.p3_samples.reserve(cfg.iterations);
                pt.p4_samples.reserve(cfg.iterations);
                pt.p5_samples.reserve(cfg.iterations);
                pt.total_samples.reserve(cfg.iterations);

                // Pre-setup TA environment for this client count (untimed TA offline precomputation)
                sim_setup_node_environment(pt.num_clients, pt.threshold, pt.degree, bench_node_id, INITIAL_LINK, &pt.cc_ctx);

                // Time Phase 0: Client Setup (snapshots K_j and consistency_data into pt.bench_node)
                if (cfg.pollute) {
                    pollute_cache(static_cast<uint32_t>(num_clients * 1000 + u_len));
                }
                uint64_t t_setup_start = get_time_ns();
                client_setup(&pt.bench_node, bench_node_id, pt.update_len);
                uint64_t t_setup_end = get_time_ns();
                pt.setup_once_us = ns_to_us(t_setup_end - t_setup_start);

                sweep_points.push_back(std::move(pt));
            }
        }
    }

    // Interleave protocol iterations across all sweep points (randomized/blocked pass design)
    // so slow-varying OS background tasks or CPU turbo-boost drift affect all configurations uniformly.
    for (int iter = 0; iter < cfg.iterations; iter++) {
        for (size_t idx = 0; idx < sweep_points.size(); idx++) {
            auto& pt = sweep_points[idx];
            uint32_t round_seed = static_cast<uint32_t>((idx + 1) * 10007 + iter + 1);
            uint32_t active_participants = static_cast<uint32_t>(pt.num_clients - pt.num_dropouts);

            // 1. Synthesize fresh random inputs for this round (untimed)
            gen_random_weights(pt.update_len, weights.data(), round_seed);

            node_set_t dropouts;
            gen_valid_dropout_list(
                pt.num_clients,
                pt.num_dropouts,
                bench_node_id,
                srv_id,
                pt.bench_node.current_link_srv,
                round_seed ^ 0xA5A5A5A5u,
                drop_msg.get(),
                &dropouts
            );

            srv_cc_result_t cc_result_msg;
            gen_valid_cc_result(srv_id, &pt.cc_ctx, drop_msg.get(), &cc_result_msg);

            gen_valid_global_update(
                srv_id,
                active_participants,
                pt.update_len,
                pt.bench_node.current_link_srv,
                round_seed ^ 0x5A5A5A5Au,
                global_msg.get()
            );

            shared_data_update.resize(pt.update_len);
            pt.bench_node.data_update.swap(shared_data_update);

            // Ensure node.cpp static thread_local vectors already have .size() == pt.update_len
            // before timing so the first N point after an M transition doesn't pay std::vector::resize zero-fill.
            if (idx == 0 || sweep_points[idx - 1].update_len != pt.update_len) {
                puf_index_t saved_ta = pt.bench_node.current_link_ta;
                puf_index_t saved_srv = pt.bench_node.current_link_srv;
                client_mask_update(&pt.bench_node, weights.data(), pt.update_len, update_msg.get());
                client_verify_global_update(&pt.bench_node, global_msg.get());
                pt.bench_node.current_link_ta = saved_ta;
                pt.bench_node.current_link_srv = saved_srv;
                pt.bench_node.current_state = node_state_compute_update;
            }

            // 2. Option C: Evict previous round's working set from L1/L2 caches
            if (cfg.pollute) {
                pollute_cache(round_seed);
            }

            // ----------------------------------------------------------------
            // PHASE 1: Mask & Sign Local Update (Node -> Server, Thesis Phase 1)
            // ----------------------------------------------------------------
            uint64_t t0 = get_time_ns();
            client_mask_update(&pt.bench_node, weights.data(), pt.update_len, update_msg.get());
            uint64_t t1 = get_time_ns();

            // ----------------------------------------------------------------
            // PHASE 2: Authenticate Dropout List & Compute CC Share w_j (Thesis Phase 4.1)
            // ----------------------------------------------------------------
            node_cc_msg_t cc_msg;
            uint64_t t2 = get_time_ns();
            client_compute_cc_value(&pt.bench_node, drop_msg.get(), &cc_msg);
            uint64_t t3 = get_time_ns();

            // ----------------------------------------------------------------
            // PHASE 3: Verify Consistency Check Result W (Server -> Node, Thesis Phase 4.3)
            // ----------------------------------------------------------------
            uint64_t t4 = get_time_ns();
            bool cc_ok = client_verify_cc_result(&pt.bench_node, drop_msg.get(), &cc_result_msg);
            uint64_t t5 = get_time_ns();

            if (!cc_ok) {
                fprintf(stderr, "[ERROR] Consistency check failed at N=%d, M=%zu, iter=%d!\n",
                        pt.num_clients, pt.update_len, iter);
                std::fclose(raw_csv);
                std::fclose(sum_csv);
                return 1;
            }

            // ----------------------------------------------------------------
            // PHASE 4: Compute & Sign Recovery Shares (Node -> Server, Thesis Phase 5)
            // ----------------------------------------------------------------
            uint64_t t6 = get_time_ns();
            client_compute_shares(&pt.bench_node, drop_msg.get(), shares_msg.get());
            uint64_t t7 = get_time_ns();

            if (shares_msg->item_cnt != static_cast<share_cnt_t>(pt.degree)) {
                fprintf(stderr, "[ERROR] Expected %d shares, got %u at N=%d, M=%zu, iter=%d!\n",
                        pt.degree, shares_msg->item_cnt, pt.num_clients, pt.update_len, iter);
                std::fclose(raw_csv);
                std::fclose(sum_csv);
                return 1;
            }

            // ----------------------------------------------------------------
            // PHASE 5: Decrypt & Verify Global Update (Server -> Node, Thesis Phase 7)
            // ----------------------------------------------------------------
            puf_index_t prev_ta = pt.bench_node.current_link_ta;
            puf_index_t prev_srv = pt.bench_node.current_link_srv;
            uint64_t t8 = get_time_ns();
            client_verify_global_update(&pt.bench_node, global_msg.get());
            uint64_t t9 = get_time_ns();

            pt.bench_node.data_update.swap(shared_data_update);

            // Wrap PUF chain links safely within CHAIN_LEN across multi-round benchmark runs
            const uint16_t ta_step = MASK_CHAIN_LEN + SHARE_CHAIN_LEN;
            const uint16_t srv_step = TRANSPORT_CHAIN_LEN;
            pt.bench_node.current_link_ta = static_cast<puf_index_t>(
                (prev_ta + ta_step) % (CHAIN_LEN - ta_step)
            );
            pt.bench_node.current_link_srv = static_cast<puf_index_t>(
                (prev_srv + srv_step) % (CHAIN_LEN - srv_step)
            );
            pt.bench_node.current_state = node_state_compute_update;

            double p1_us = ns_to_us(t1 - t0);
            double p2_us = ns_to_us(t3 - t2);
            double p3_us = ns_to_us(t5 - t4);
            double p4_us = ns_to_us(t7 - t6);
            double p5_us = ns_to_us(t9 - t8);
            double total_us = p1_us + p2_us + p3_us + p4_us + p5_us;

            pt.p1_samples.push_back(p1_us);
            pt.p2_samples.push_back(p2_us);
            pt.p3_samples.push_back(p3_us);
            pt.p4_samples.push_back(p4_us);
            pt.p5_samples.push_back(p5_us);
            pt.total_samples.push_back(total_us);
        }
        fprintf(stderr, "\r[Progress] Completed pass %d / %d across all %zu configurations...",
                iter + 1, cfg.iterations, sweep_points.size());
        std::fflush(stderr);
    }
    fprintf(stderr, "\r                                                                        \r");
    std::fflush(stderr);

    for (const auto& pt : sweep_points) {
        for (int iter = 0; iter < cfg.iterations; iter++) {
            std::fprintf(raw_csv, "%d,%d,%zu,%d,%d,%.1f,%d,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
                         pt.num_clients, pt.degree, pt.update_len, pt.threshold,
                         pt.num_dropouts, pt.dropout_pct, iter + 1,
                         (iter == 0) ? pt.setup_once_us : 0.0,
                         pt.p1_samples[iter], pt.p2_samples[iter], pt.p3_samples[iter],
                         pt.p4_samples[iter], pt.p5_samples[iter], pt.total_samples[iter]);
        }
        std::fflush(raw_csv);

        std::vector<double> setup_samples(cfg.iterations, pt.setup_once_us);
        PhaseStats st_setup = compute_stats(setup_samples);
        PhaseStats st_p1 = compute_stats(pt.p1_samples);
        PhaseStats st_p2 = compute_stats(pt.p2_samples);
        PhaseStats st_p3 = compute_stats(pt.p3_samples);
        PhaseStats st_p4 = compute_stats(pt.p4_samples);
        PhaseStats st_p5 = compute_stats(pt.p5_samples);
        PhaseStats st_total = compute_stats(pt.total_samples);

        std::fprintf(sum_csv,
            "%d,%d,%zu,%d,%d,%.1f,%d,"
            "%.3f,%.3f,"
            "%.3f,%.3f,%.3f,%.3f,%.3f,"
            "%.3f,%.3f,%.3f,%.3f,%.3f,"
            "%.3f,%.3f,%.3f,%.3f,%.3f,"
            "%.3f,%.3f,%.3f,%.3f,%.3f,"
            "%.3f,%.3f,%.3f,%.3f,%.3f,"
            "%.3f,%.3f,%.3f,%.3f,%.3f\n",
            pt.num_clients, pt.degree, pt.update_len, pt.threshold,
            pt.num_dropouts, pt.dropout_pct, cfg.iterations,
            st_setup.mean_us, st_setup.stdev_us,
            st_p1.mean_us, st_p1.stdev_us, st_p1.median_us, st_p1.min_us, st_p1.max_us,
            st_p2.mean_us, st_p2.stdev_us, st_p2.median_us, st_p2.min_us, st_p2.max_us,
            st_p3.mean_us, st_p3.stdev_us, st_p3.median_us, st_p3.min_us, st_p3.max_us,
            st_p4.mean_us, st_p4.stdev_us, st_p4.median_us, st_p4.min_us, st_p4.max_us,
            st_p5.mean_us, st_p5.stdev_us, st_p5.median_us, st_p5.min_us, st_p5.max_us,
            st_total.mean_us, st_total.stdev_us, st_total.median_us, st_total.min_us, st_total.max_us
        );
        std::fflush(sum_csv);

        char drop_col[32];
        std::snprintf(drop_col, sizeof(drop_col), "%d(%.0f%%)", pt.num_dropouts, pt.dropout_pct);

        printf("%-5d %-6zu %-5d %-4d %-11s | %9.2f | %7.2f +/- %-5.2f | %5.2f +/- %-5.2f | %7.2f +/- %-5.2f | %9.2f +/- %-6.2f | %7.2f +/- %-5.2f | %9.2f +/- %-6.2f\n",
               pt.num_clients, pt.update_len, pt.degree, pt.threshold, drop_col,
               pt.setup_once_us,
               st_p1.mean_us, st_p1.stdev_us,
               st_p2.mean_us, st_p2.stdev_us,
               st_p3.mean_us, st_p3.stdev_us,
               st_p4.mean_us, st_p4.stdev_us,
               st_p5.mean_us, st_p5.stdev_us,
               st_total.mean_us, st_total.stdev_us);
        std::fflush(stdout);
    }

    std::fclose(raw_csv);
    std::fclose(sum_csv);

    printf("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
    printf("Benchmark finished. Raw data saved to '%s', summary saved to '%s'.\n",
           cfg.raw_csv_path.c_str(), cfg.summary_csv_path.c_str());
    return 0;
}
