import math
from dataclasses import dataclass

import numpy as np


UINT32_MOD = 2**32
UINT32_SIGN_BIT = 2**31


@dataclass
class VariantResult:
    """Final model and metrics for one federated strategy."""

    name: str
    model: object
    metrics: list


def flatten_weights(weights):
    """Convert Keras layer tensors into one vector and remember their layout."""
    shapes = [w.shape for w in weights]
    sizes = [w.size for w in weights]
    flat = np.concatenate([w.reshape(-1) for w in weights]).astype(np.float32)
    return flat, shapes, sizes


def unflatten_weights(flat, shapes, sizes):
    """Restore a flattened model vector into Keras' list-of-arrays format."""
    weights = []
    cursor = 0
    for shape, size in zip(shapes, sizes):
        weights.append(flat[cursor : cursor + size].reshape(shape).astype(np.float32))
        cursor += size
    return weights


def encode_fixed_point(values, scale):
    """Map signed float values to uint32 for modular secure summation."""
    signed = np.rint(values.astype(np.float64) * scale).astype(np.int64)
    if (
        signed.min(initial=0) < -UINT32_SIGN_BIT
        or signed.max(initial=0) >= UINT32_SIGN_BIT
    ):
        raise OverflowError(
            "Fixed-point values exceed signed int32 range. Lower QUANT_SCALE."
        )

    return np.mod(signed, UINT32_MOD).astype(np.uint32)


def decode_fixed_point(values, scale):
    """Invert encode_fixed_point after the server returns the modular sum."""
    unsigned = values.astype(np.uint64)
    signed = unsigned.astype(np.int64)
    signed[unsigned >= UINT32_SIGN_BIT] -= UINT32_MOD
    return signed.astype(np.float32) / float(scale)


def heversa_secure_sum_uint32(
    heversa,
    encoded_client_vectors,
    num_clients,
    threshold,
    update_len,
    chunk_log_interval,
):
    """Securely sum uint32 client vectors using the existing HeVerSa API."""
    total_len = encoded_client_vectors[0].size
    padded_len = int(math.ceil(total_len / update_len) * update_len)
    padded_clients = []

    for vec in encoded_client_vectors:
        if vec.size != total_len:
            raise ValueError("All client vectors must have the same length.")
        padded = np.zeros(padded_len, dtype=np.uint32)
        padded[:total_len] = vec
        padded_clients.append(padded)

    summed = np.zeros(padded_len, dtype=np.uint32)
    total_chunks = padded_len // update_len

    for chunk_idx in range(total_chunks):
        start = chunk_idx * update_len
        end = start + update_len

        server = heversa.Server()
        heversa.ta_setup_protocol(num_clients, threshold, server)

        clients = [heversa.Node() for _ in range(num_clients)]
        for client_id, client in enumerate(clients):
            heversa.client_setup(client, client_id)

        for client_id, client in enumerate(clients):
            chunk = np.ascontiguousarray(
                padded_clients[client_id][start:end], dtype=np.uint32
            )
            msg = heversa.client_mask_update(client, chunk)
            heversa.server_receive_update(server, msg)

        drop_msg, _ = heversa.server_broadcast_dropouts(server)

        for client in clients:
            share_msg = heversa.client_compute_shares(client, drop_msg)
            if share_msg.item_cnt > 0:
                heversa.server_receive_shares(server, share_msg)

        summed[start:end] = heversa.server_aggregate_updates(server)

        if chunk_log_interval and (
            chunk_idx == 0
            or chunk_idx + 1 == total_chunks
            or (chunk_idx + 1) % chunk_log_interval == 0
        ):
            print(
                f"secure aggregation chunk {chunk_idx + 1}/{total_chunks}",
                flush=True,
            )

    return summed[:total_len]


def aggregate_weights_secure(
    heversa,
    local_weight_sets,
    client_sample_counts,
    quant_scale,
    num_clients,
    threshold,
    update_len,
    chunk_log_interval,
):
    """FedAvg aggregation where the weighted sum is computed by HeVerSa."""
    total_samples = float(sum(client_sample_counts))
    encoded_clients = []
    shapes = None
    sizes = None

    for weights, count in zip(local_weight_sets, client_sample_counts):
        flat, local_shapes, local_sizes = flatten_weights(weights)
        shapes = local_shapes
        sizes = local_sizes
        scaled_flat = flat * (count / total_samples)
        encoded_clients.append(encode_fixed_point(scaled_flat, quant_scale))

    summed_encoded = heversa_secure_sum_uint32(
        heversa=heversa,
        encoded_client_vectors=encoded_clients,
        num_clients=num_clients,
        threshold=threshold,
        update_len=update_len,
        chunk_log_interval=chunk_log_interval,
    )
    aggregated_flat = decode_fixed_point(summed_encoded, quant_scale)

    return unflatten_weights(aggregated_flat, shapes, sizes)


def aggregate_weights_plain(local_weight_sets, client_sample_counts):
    """Ordinary FedAvg aggregation without HeVerSa masking."""
    total_samples = float(sum(client_sample_counts))
    averaged = [
        np.zeros_like(weight, dtype=np.float64) for weight in local_weight_sets[0]
    ]

    for weights, count in zip(local_weight_sets, client_sample_counts):
        scale = count / total_samples
        for idx, weight in enumerate(weights):
            averaged[idx] += weight.astype(np.float64) * scale

    return [weight.astype(np.float32) for weight in averaged]


class FederatedStrategy:
    """Small extension point for changing FL algorithms later."""

    def __init__(self, name, model_builder, clear_session, keras_verbose):
        self.name = name
        self.model_builder = model_builder
        self.clear_session = clear_session
        self.keras_verbose = keras_verbose

    def create_model(self):
        return self.model_builder()

    def fit_client_model(self, model, x_client, y_client, args):
        model.fit(
            x_client,
            y_client,
            epochs=args.local_epochs,
            batch_size=args.batch_size,
            verbose=self.keras_verbose,
            shuffle=True,
        )

    def train_client(self, client_id, client_data, global_weights, args):
        x_client, y_client = client_data
        print(
            f"{self.name}: training client {client_id} on {len(x_client)} samples",
            flush=True,
        )

        local_model = self.create_model()
        local_model.set_weights(global_weights)
        self.fit_client_model(local_model, x_client, y_client, args)
        local_weights = local_model.get_weights()
        self.clear_session()

        return local_weights, len(x_client)

    def aggregate(self, local_weight_sets, client_sample_counts):
        raise NotImplementedError


class FedAvgPlainStrategy(FederatedStrategy):
    """FedAvg with ordinary plaintext weighted averaging."""

    def __init__(
        self,
        model_builder,
        clear_session,
        keras_verbose,
        name="fedavg_plain",
    ):
        super().__init__(
            name=name,
            model_builder=model_builder,
            clear_session=clear_session,
            keras_verbose=keras_verbose,
        )

    def aggregate(self, local_weight_sets, client_sample_counts):
        return aggregate_weights_plain(local_weight_sets, client_sample_counts)


class FedAvgHeVersaStrategy(FederatedStrategy):
    """FedAvg where the weighted sum is delegated to HeVerSa."""

    def __init__(
        self,
        heversa,
        protocol_config,
        model_builder,
        clear_session,
        keras_verbose,
        name="fedavg_heversa",
    ):
        super().__init__(
            name=name,
            model_builder=model_builder,
            clear_session=clear_session,
            keras_verbose=keras_verbose,
        )
        self.heversa = heversa
        self.protocol_config = protocol_config

    def aggregate(self, local_weight_sets, client_sample_counts):
        return aggregate_weights_secure(
            heversa=self.heversa,
            local_weight_sets=local_weight_sets,
            client_sample_counts=client_sample_counts,
            quant_scale=self.protocol_config.quant_scale,
            num_clients=self.protocol_config.num_clients,
            threshold=self.protocol_config.threshold,
            update_len=self.protocol_config.update_len,
            chunk_log_interval=self.protocol_config.chunk_log_interval,
        )


def build_strategies(
    heversa,
    protocol_config,
    model_builder,
    clear_session,
    keras_verbose,
):
    """Return the plain and HeVerSa-backed FedAvg variants."""
    return [
        FedAvgPlainStrategy(model_builder, clear_session, keras_verbose),
        FedAvgHeVersaStrategy(
            heversa=heversa,
            protocol_config=protocol_config,
            model_builder=model_builder,
            clear_session=clear_session,
            keras_verbose=keras_verbose,
        ),
    ]


def train_federated_variant(strategy, initial_weights, client_data, test_data, args):
    """Train one strategy and return its final model plus round metrics."""
    x_test, y_test = test_data

    global_model = strategy.create_model()
    global_model.set_weights(initial_weights)
    metrics = []

    print(f"\nStarting {strategy.name}", flush=True)

    for round_idx in range(args.rounds):
        print(f"\n{strategy.name} round {round_idx + 1}/{args.rounds}", flush=True)
        global_weights = global_model.get_weights()
        local_weight_sets = []
        client_sample_counts = []

        for client_id, (x_client, y_client) in enumerate(client_data):
            local_weights, sample_count = strategy.train_client(
                client_id=client_id,
                client_data=(x_client, y_client),
                global_weights=global_weights,
                args=args,
            )
            local_weight_sets.append(local_weights)
            client_sample_counts.append(sample_count)

        global_model.set_weights(
            strategy.aggregate(local_weight_sets, client_sample_counts)
        )

        loss, accuracy = global_model.evaluate(
            x_test,
            y_test,
            batch_size=args.batch_size,
            verbose=0,
        )
        round_metrics = {
            "round": round_idx + 1,
            "test_loss": float(loss),
            "test_accuracy": float(accuracy),
        }
        metrics.append(round_metrics)
        print(
            f"{strategy.name} round {round_idx + 1}: "
            f"test_loss={loss:.4f}, test_accuracy={accuracy:.4f}",
            flush=True,
        )

    return VariantResult(strategy.name, global_model, metrics)
