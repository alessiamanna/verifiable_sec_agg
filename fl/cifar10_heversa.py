import argparse
import importlib
import importlib.machinery
import json
import math
import os
import random
import sys
import tempfile
import warnings
from dataclasses import dataclass
from pathlib import Path

import numpy as np

try:
    from .fedavg import (
        build_strategies as build_fedavg_strategies,
        flatten_weights,
        train_federated_variant,
    )
except ImportError:
    from fedavg import (
        build_strategies as build_fedavg_strategies,
        flatten_weights,
        train_federated_variant,
    )


tf = None


# These constants mirror the current generated PUF data and C++ protocol setup.
NUM_CLIENTS = 10
THRESHOLD = 2
UPDATE_LEN = 16

# Fixed-point scale used before values are packed into uint32 for HeVerSa.
QUANT_SCALE = 1_000_000.0

# Local script defaults. They are constants because they are implementation
# details for this prototype, not protocol parameters to tune from the CLI.
CHUNK_LOG_INTERVAL = 25
KERAS_VERBOSE = 2
REPRESENTATIVE_SAMPLES = 256
SUPPORTED_FL_FRAMEWORKS = ("fedavg", "fedavg_qat")
MODEL_OUTPUT_DIR = Path("fl/models")
RESULT_OUTPUT_DIR = Path("fl/results")
KERAS_HOME_DIR = Path(".keras")


@dataclass(frozen=True)
class ProtocolConfig:
    """Runtime constants shared by HeVerSa and the FL experiment."""

    num_clients: int = NUM_CLIENTS
    threshold: int = THRESHOLD
    update_len: int = UPDATE_LEN
    quant_scale: float = QUANT_SCALE
    chunk_log_interval: int = CHUNK_LOG_INTERVAL

def import_tensorflow():
    """Import TensorFlow lazily so HeVerSa build errors stay readable."""
    global tf

    if tf is None:
        keras_home = Path(__file__).resolve().parents[1] / KERAS_HOME_DIR
        os.environ.setdefault("KERAS_HOME", str(keras_home))
        keras_home.mkdir(parents=True, exist_ok=True)

        # TensorFlow 1.14 emits this with newer NumPy during import. It is noisy
        # but not actionable for this training script.
        warnings.filterwarnings(
            "ignore",
            category=FutureWarning,
            message=r"Passing \(type, 1\) or '1type' as a synonym of type is deprecated.*",
        )
        import tensorflow as tensorflow

        tf = tensorflow

    return tf


def set_random_seed(seed):
    """Set random seeds across TensorFlow versions used by this project."""
    random.seed(seed)
    np.random.seed(seed)

    if hasattr(tf.keras.utils, "set_random_seed"):
        tf.keras.utils.set_random_seed(seed)
    elif (
        hasattr(tf, "compat")
        and hasattr(tf.compat, "v1")
        and hasattr(tf.compat.v1, "set_random_seed")
    ):
        tf.compat.v1.set_random_seed(seed)
    elif hasattr(tf, "set_random_seed"):
        tf.set_random_seed(seed)


def find_heversa_module_dirs(repo_root):
    """Return likely directories containing the built HeVerSa extension."""
    module_dirs = []

    for build_dir in (repo_root / "build", repo_root / "build-clang"):
        if not build_dir.exists():
            continue

        suffixes = set(importlib.machinery.EXTENSION_SUFFIXES)
        suffixes.update({".pyd", ".so"})
        for suffix in suffixes:
            for module_path in build_dir.rglob(f"heversa*{suffix}"):
                module_dirs.append(module_path.parent)

    return sorted(set(module_dirs))


def import_heversa(repo_root):
    """Import the pybind11 module from common CMake output locations."""
    search_paths = find_heversa_module_dirs(repo_root) + [
        repo_root / "build",
        repo_root / "build" / "Release",
        repo_root / "build" / "Debug",
        repo_root / "build" / "RelWithDebInfo",
        repo_root / "build-clang",
        repo_root / "build-clang" / "Release",
        repo_root / "build-clang" / "Debug",
        repo_root / "build-clang" / "RelWithDebInfo",
        repo_root,
    ]

    # CMake on Windows commonly places .pyd files in build/{Release,Debug}.
    for path in search_paths:
        path_str = str(path)
        if path.exists() and path_str not in sys.path:
            sys.path.insert(0, path_str)

    try:
        return importlib.import_module("heversa")
    except ModuleNotFoundError as exc:
        if exc.name != "heversa":
            raise

        searched = "\n".join(f"  - {path}" for path in search_paths if path.exists())
        if not searched:
            searched = "  - no existing build output directories"

        raise ModuleNotFoundError(
            "Could not import the heversa Python module. No built extension "
            "matching heversa*.pyd or heversa*.so was found.\n\n"
            f"Searched:\n{searched}\n\n"
            "Build it with CMake using the same Python environment that runs "
            "this script:\n"
            f'  cmake -S "{repo_root}" -B "{repo_root / "build"}" '
            f'-DPython_EXECUTABLE="{Path(sys.executable)}" '
            f'-DCMAKE_CXX_FLAGS="/DMAX_NUM_CLIENTS={NUM_CLIENTS}"\n'
            f'  cmake --build "{repo_root / "build"}" --config Release '
            "--target heversa\n\n"
            "If Windows says cmake is not recognized, install CMake or add it "
            "to PATH inside the heversa Conda environment first."
        ) from exc


def build_cifar10_cnn():
    """Small TFLite-friendly CNN with ops supported on embedded targets."""
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=(32, 32, 3)),
            tf.keras.layers.Conv2D(8, 3, padding="same", activation="relu"),
            tf.keras.layers.MaxPooling2D(),
            tf.keras.layers.Conv2D(16, 3, padding="same", activation="relu"),
            tf.keras.layers.GlobalAveragePooling2D(),
            tf.keras.layers.Dense(10, activation="softmax"),
        ]
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(),
        loss=tf.keras.losses.SparseCategoricalCrossentropy(),
        metrics=["accuracy"],
    )
    return model


def representative_dataset(x_samples, max_samples):
    """Representative samples let TFLite calibrate full-integer quantization."""
    limit = min(len(x_samples), max_samples)
    for idx in range(limit):
        yield [x_samples[idx : idx + 1].astype(np.float32)]


def convert_to_tflite(model, x_representative, representative_samples):
    """Convert the trained global Keras model into an int8 TFLite model."""
    saved_model_dir = None

    try:
        if hasattr(tf.lite.TFLiteConverter, "from_keras_model"):
            converter = tf.lite.TFLiteConverter.from_keras_model(model)
        else:
            saved_model_dir = tempfile.TemporaryDirectory()
            tf.keras.experimental.export_saved_model(model, saved_model_dir.name)
            converter = tf.lite.TFLiteConverter.from_saved_model(saved_model_dir.name)

        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        converter.representative_dataset = lambda: representative_dataset(
            x_representative, representative_samples
        )
        if hasattr(converter, "target_spec"):
            converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
        else:
            converter.target_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
        converter.inference_input_type = tf.int8
        converter.inference_output_type = tf.int8

        return converter.convert()
    finally:
        if saved_model_dir is not None:
            saved_model_dir.cleanup()



def save_tflite_model(model, x_representative, output_path, samples):
    """Write the final global model in TensorFlow Lite format for the board."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tflite_model = convert_to_tflite(
        model=model,
        x_representative=x_representative,
        representative_samples=samples,
    )
    output_path.write_bytes(tflite_model)
    print(f"saved TFLite model to {output_path}")


def quantize_tflite_input(batch, input_details):
    """Apply the TFLite input tensor's scale/zero-point when it is integer."""
    dtype = input_details["dtype"]
    if not np.issubdtype(dtype, np.integer):
        return batch.astype(np.float32)

    scale, zero_point = input_details["quantization"]
    if scale == 0:
        raise ValueError("TFLite input tensor has invalid quantization scale 0.")

    q_batch = np.rint(batch / scale + zero_point)
    info = np.iinfo(dtype)
    return np.clip(q_batch, info.min, info.max).astype(dtype)


def evaluate_tflite_model(tflite_path, x_test, y_test):
    """Run a simple accuracy check through the TFLite interpreter."""
    interpreter = tf.lite.Interpreter(model_path=str(tflite_path))
    interpreter.allocate_tensors()

    input_details = interpreter.get_input_details()[0]
    output_details = interpreter.get_output_details()[0]
    correct = 0

    for idx in range(len(x_test)):
        batch = x_test[idx : idx + 1]
        interpreter.set_tensor(
            input_details["index"],
            quantize_tflite_input(batch, input_details),
        )
        interpreter.invoke()
        logits = interpreter.get_tensor(output_details["index"])
        correct += int(np.argmax(logits, axis=1)[0] == y_test[idx])

    accuracy = correct / len(x_test)
    print(f"TFLite test_accuracy={accuracy:.4f}")
    return accuracy


def split_iid(x, y, num_clients, seed):
    """Create a simple IID partition of CIFAR-10 across clients."""
    rng = np.random.default_rng(seed)
    indices = np.arange(len(x))
    rng.shuffle(indices)
    shards = np.array_split(indices, num_clients)
    return [(x[idx], y[idx]) for idx in shards]


def load_cifar10_clients(num_clients, train_limit, test_limit, seed):
    """Load CIFAR-10, normalize images, and split train data by client."""
    (x_train, y_train), (x_test, y_test) = tf.keras.datasets.cifar10.load_data()
    x_train = x_train.astype(np.float32) / 255.0
    x_test = x_test.astype(np.float32) / 255.0
    y_train = y_train.reshape(-1).astype(np.int64)
    y_test = y_test.reshape(-1).astype(np.int64)

    if train_limit is not None:
        x_train = x_train[:train_limit]
        y_train = y_train[:train_limit]
    if test_limit is not None:
        x_test = x_test[:test_limit]
        y_test = y_test[:test_limit]

    return split_iid(x_train, y_train, num_clients, seed), (x_test, y_test)


def build_framework_strategies(framework_name, heversa, protocol_config):
    """Build the comparison variants for the selected FL framework."""
    if framework_name == "fedavg":
        return build_fedavg_strategies(
            heversa=heversa,
            protocol_config=protocol_config,
            model_builder=build_cifar10_cnn,
            clear_session=tf.keras.backend.clear_session,
            keras_verbose=KERAS_VERBOSE,
        )

    if framework_name == "fedavg_qat":
        try:
            from .fedavg_qat import (
                build_strategies as build_fedavg_qat_strategies,
            )
        except ImportError:
            from fedavg_qat import (
                build_strategies as build_fedavg_qat_strategies,
            )

        return build_fedavg_qat_strategies(
            heversa=heversa,
            protocol_config=protocol_config,
            clear_session=tf.keras.backend.clear_session,
            keras_verbose=KERAS_VERBOSE,
        )

    raise ValueError(f"Unsupported FL framework: {framework_name}")


def add_framework_config(framework_name, payload):
    """Attach framework-specific metadata to the result payload."""
    if framework_name == "fedavg_qat":
        try:
            from .fedavg_qat import add_qat_config
        except ImportError:
            from fedavg_qat import add_qat_config

        return add_qat_config(payload)

    return payload


def safe_name(name):
    """Return a filesystem-friendly name fragment."""
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def model_output_path(strategy_name):
    """Derive the TFLite output path from the selected strategy."""
    return MODEL_OUTPUT_DIR / f"cifar10_{safe_name(strategy_name)}_int8.tflite"


def results_output_path(strategy_names):
    """Derive the JSON output path from the selected strategy comparison."""
    comparison_name = "_vs_".join(safe_name(name) for name in strategy_names)
    return RESULT_OUTPUT_DIR / f"cifar10_{comparison_name}.json"


def compare_final_metrics(baseline_name, baseline_metrics, candidate_name, candidate_metrics):
    """Return final candidate-minus-baseline deltas for common metrics."""
    if not baseline_metrics or not candidate_metrics:
        return {}

    baseline_final = baseline_metrics[-1]
    candidate_final = candidate_metrics[-1]
    candidate = safe_name(candidate_name)
    baseline = safe_name(baseline_name)

    return {
        f"test_loss_delta_{candidate}_minus_{baseline}": (
            candidate_final["test_loss"] - baseline_final["test_loss"]
        ),
        f"test_accuracy_delta_{candidate}_minus_{baseline}": (
            candidate_final["test_accuracy"] - baseline_final["test_accuracy"]
        ),
    }


def results_payload(args, protocol_config, strategy_names, metrics_by_variant, model_outputs):
    """Build the serializable experiment report."""
    comparison = {}

    if len(strategy_names) >= 2:
        baseline_name = strategy_names[0]
        candidate_name = strategy_names[1]
        comparison = compare_final_metrics(
            baseline_name=baseline_name,
            baseline_metrics=metrics_by_variant.get(baseline_name),
            candidate_name=candidate_name,
            candidate_metrics=metrics_by_variant.get(candidate_name),
        )

    return {
        "config": {
            "fl_framework": args.fl_framework,
            "clients": protocol_config.num_clients,
            "threshold": protocol_config.threshold,
            "update_len": protocol_config.update_len,
            "rounds": args.rounds,
            "local_epochs": args.local_epochs,
            "batch_size": args.batch_size,
            "train_limit": args.train_limit,
            "test_limit": args.test_limit,
            "seed": args.seed,
            "quant_scale": protocol_config.quant_scale,
        },
        "model_outputs": model_outputs,
        **metrics_by_variant,
        "comparison": comparison,
    }


def save_comparison_results(output_path, payload):
    """Save the experiment report as JSON."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"saved comparison results to {output_path}")


def save_variant_tflite(result, output_path, representative_x, test_data, eval_tflite):
    """Save one trained strategy model and optionally record TFLite accuracy."""
    if not output_path:
        return

    save_tflite_model(
        model=result.model,
        x_representative=representative_x,
        output_path=output_path,
        samples=REPRESENTATIVE_SAMPLES,
    )

    if eval_tflite and result.metrics:
        tflite_accuracy = evaluate_tflite_model(output_path, *test_data)
        result.metrics[-1]["tflite_test_accuracy"] = float(tflite_accuracy)


def train(args):
    repo_root = Path(__file__).resolve().parents[1]
    heversa = import_heversa(repo_root)
    import_tensorflow()
    protocol_config = ProtocolConfig()

    set_random_seed(args.seed)

    client_data, test_data = load_cifar10_clients(
        num_clients=protocol_config.num_clients,
        train_limit=args.train_limit,
        test_limit=args.test_limit,
        seed=args.seed,
    )

    strategies = build_framework_strategies(
        framework_name=args.fl_framework,
        heversa=heversa,
        protocol_config=protocol_config,
    )

    seed_model = strategies[0].create_model()
    initial_weights = seed_model.get_weights()
    initial_flat, _, _ = flatten_weights(initial_weights)
    tf.keras.backend.clear_session()

    print(f"Starting CIFAR-10 {args.fl_framework} comparison")
    print(f"clients: {protocol_config.num_clients}")
    print(f"rounds: {args.rounds}")
    print(f"local epochs: {args.local_epochs}")
    print(f"model parameters: {initial_flat.size}")
    print(
        f"secure chunks per round: "
        f"{math.ceil(initial_flat.size / protocol_config.update_len)}"
    )

    results = []

    for strategy in strategies:
        # Reset each strategy branch to the same stochastic state so the
        # comparison isolates aggregation differences as much as possible.
        set_random_seed(args.seed)
        results.append(
            train_federated_variant(
                strategy=strategy,
                initial_weights=initial_weights,
                client_data=client_data,
                test_data=test_data,
                args=args,
            )
        )

    results_by_name = {result.name: result for result in results}
    metrics_by_variant = {
        name: result.metrics for name, result in results_by_name.items()
    }
    strategy_names = [result.name for result in results]
    model_outputs = {
        result.name: str(model_output_path(result.name)) for result in results
    }

    representative_x = np.concatenate([x_client for x_client, _ in client_data], axis=0)

    for name, output_path in model_outputs.items():
        save_variant_tflite(
            result=results_by_name[name],
            output_path=output_path,
            representative_x=representative_x,
            test_data=test_data,
            eval_tflite=args.eval_tflite,
        )

    payload = results_payload(
        args=args,
        protocol_config=protocol_config,
        strategy_names=strategy_names,
        metrics_by_variant=metrics_by_variant,
        model_outputs=model_outputs,
    )
    save_comparison_results(
        results_output_path(strategy_names),
        add_framework_config(args.fl_framework, payload),
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="CIFAR-10 FL comparison with optional HeVerSa aggregation."
    )
    parser.add_argument(
        "--fl-framework",
        choices=SUPPORTED_FL_FRAMEWORKS,
        default="fedavg",
    )
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--local-epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--train-limit", type=int, default=8000)
    parser.add_argument("--test-limit", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=26)
    parser.add_argument("--eval-tflite", action="store_true")
    return parser.parse_args()


def main():
    train(parse_args())


if __name__ == "__main__":
    main()
