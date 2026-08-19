import numpy as np
import heversa

NUM_CLIENTS = 4
THRESHOLD = 2
UPDATE_LEN = 16


print("=== Starting HeVerSa API in Python ===")

# helper -> targets. This is sparse: 8 directed recovery edges instead of 12.
# With client 2 dropped, every target still has at least THRESHOLD live helpers.
RECOVERY_TOPOLOGY = [
    [1, 2, 3],  # client 0 can recover clients 1, 2, 3
    [0, 2, 3],  # client 1 can recover clients 0, 2, 3
    [],         # client 2 drops in this test, so it does not need helper duties
    [0, 1],     # client 3 can recover clients 0, 1
]

server = heversa.Server()
heversa.configure_recovery_topology(NUM_CLIENTS, RECOVERY_TOPOLOGY)
heversa.ta_setup_protocol(NUM_CLIENTS, THRESHOLD, server)

clients = [heversa.Node() for _ in range(NUM_CLIENTS)]
for i in range(NUM_CLIENTS):
    heversa.client_setup(clients[i], i)

weights = [np.full(UPDATE_LEN, (i + 1) * 10, dtype=np.uint32) for i in range(NUM_CLIENTS)]

print("\n--- PHASE 1: Local Updates ---")
for i in range(NUM_CLIENTS):
    msg = heversa.client_mask_update(clients[i], weights[i])

    if i == 2:
        print(f"[Python] Dropping Client {i}")
        continue 

    heversa.server_receive_update(server, msg)


print("\n--- PHASE 2: Share Exchange ---")
drop_msg, dropouts = heversa.server_broadcast_dropouts(server)
print(f"[Python] Server detected dropouts: {dropouts.ids}")

active_nodes = [i for i in range(NUM_CLIENTS) if i != 2]
for i in active_nodes:
    share_msg = heversa.client_compute_shares(clients[i], drop_msg)
    if share_msg.item_cnt > 0:
        heversa.server_receive_shares(server, share_msg)


print("\n--- PHASE 3: Final Aggregation ---")
final_model = heversa.server_aggregate_updates(server)

print("\n=== FINAL UNMASKED WEIGHTS (NUMPY ARRAY) ===")
print(final_model)

