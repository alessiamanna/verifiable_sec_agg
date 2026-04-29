import heversa
import numpy as np

NUM_CLIENTS = 4
THRESHOLD = 2
UPDATE_LEN = 16

print("=== Starting HeVerSa API in Python ===")


server = heversa.Server()
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
print(f"[Python] Server detected {dropouts.node_count} dropouts")


active_nodes = [i for i in range(NUM_CLIENTS) if i != 2]
for i in active_nodes:
    share_msg = heversa.client_compute_shares(clients[i], drop_msg)
    if share_msg.item_cnt > 0:
        heversa.server_receive_shares(server, share_msg)


print("\n--- PHASE 3: Final Aggregation ---")
final_model = heversa.server_aggregate_updates(server)

print("\n=== FINAL UNMASKED WEIGHTS (NUMPY ARRAY) ===")
print(final_model)