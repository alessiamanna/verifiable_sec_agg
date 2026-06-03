import argparse
import contextlib
import hashlib
import importlib
import importlib.machinery
import json
import math
import os
import pickle
import random
import shutil
import sys
import tempfile
import time
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

try:
    from . import cnn, cnn_medium, mlp, mlp_medium
except ImportError:
    import cnn
    import cnn_medium
    import mlp
    import mlp_medium


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
SUPPORTED_DATASETS = ("cifar10", "mnist", "organamnist")
SUPPORTED_NETWORKS = ("cnn", "cnn_medium", "mlp", "mlp_medium")
FRAMEWORK_STRATEGY_NAMES = {
    "fedavg": ("fedavg_plain", "fedavg_heversa"),
    "fedavg_qat": ("fedavg_qat_plain", "fedavg_qat_heversa"),
}
MODEL_OUTPUT_DIR = Path("fl/models")
RESULT_OUTPUT_DIR = Path("fl/results")
KERAS_HOME_DIR = Path(".keras")
MEDMNIST_CACHE_DIR = KERAS_HOME_DIR / "medmnist"
ORGANAMNIST_FILENAME = "organamnist.npz"
ORGANAMNIST_URL = "https://zenodo.org/records/10519652/files/organamnist.npz?download=1"
ORGANAMNIST_MD5 = "68e3f8846a6bd62f0c9bf841c0d9eacc"
NETWORK_MODULES = {
    "cnn": cnn,
    "cnn_medium": cnn_medium,
    "mlp": mlp,
    "mlp_medium": mlp_medium,
}
DATASET_LOCK_POLL_SECONDS = 5
DATASET_CORRUPTION_EXCEPTIONS = (
    EOFError,
    OSError,
    ValueError,
    pickle.UnpicklingError,
)


@dataclass(frozen=True)
class DatasetConfig:
    """Dataset metadata needed by loaders and model builders."""

    name: str
    display_name: str
    input_shape: tuple
    num_classes: int


@dataclass(frozen=True)
class ProtocolConfig:
    """Runtime constants shared by HeVerSa and the FL experiment."""

    num_clients: int = NUM_CLIENTS
    threshold: int = THRESHOLD
    update_len: int = UPDATE_LEN
    quant_scale: float = QUANT_SCALE
    chunk_log_interval: int = CHUNK_LOG_INTERVAL


DATASET_CONFIGS = {
    "cifar10": DatasetConfig(
        name="cifar10",
        display_name="CIFAR-10",
        input_shape=(32, 32, 3),
        num_classes=10,
    ),
    "mnist": DatasetConfig(
        name="mnist",
        display_name="MNIST",
        input_shape=(28, 28, 1),
        num_classes=10,
    ),
    "organamnist": DatasetConfig(
        name="organamnist",
        display_name="OrganAMNIST",
        input_shape=(28, 28, 1),
        num_classes=11,
    ),
}


def keras_home_path():
    """Return the repo-local Keras cache directory."""
    return Path(
        os.environ.get(
            "KERAS_HOME",
            Path(__file__).resolve().parents[1] / KERAS_HOME_DIR,
        )
    )


@contextlib.contextmanager
def dataset_cache_lock(dataset_name):
    """Serialize dataset cache downloads/extracts across Slurm jobs."""
    lock_root = keras_home_path() / "locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / f"{dataset_name}.lock"
    lock_file = lock_path.open("w", encoding="utf-8")

    try:
        try:
            import fcntl
        except ImportError:
            yield
            return

        print(f"waiting for {dataset_name} dataset cache lock", flush=True)
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        print(f"acquired {dataset_name} dataset cache lock", flush=True)
        yield
    finally:
        try:
            if "fcntl" in locals():
                fcntl.flock(lock_file, fcntl.LOCK_UN)
        finally:
            lock_file.close()


def remove_keras_dataset_cache(*prefixes):
    """Remove selected repo-local Keras dataset cache entries."""
    dataset_dir = keras_home_path() / "datasets"
    for prefix in prefixes:
        for path in dataset_dir.glob(f"{prefix}*"):
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()


def load_dataset_with_cache_retry(dataset_name, cache_prefixes, load_fn):
    """Load a dataset, clearing its cache once if it was partially written."""
    with dataset_cache_lock(dataset_name):
        try:
            return load_fn()
        except DATASET_CORRUPTION_EXCEPTIONS as exc:
            print(
                f"{dataset_name} cache looks corrupted ({exc}); "
                "clearing cache and retrying once",
                flush=True,
            )
            remove_keras_dataset_cache(*cache_prefixes)
            time.sleep(DATASET_LOCK_POLL_SECONDS)
            return load_fn()


def import_tensorflow():
    """Import TensorFlow lazily so HeVerSa build errors stay readable."""
    global tf

    if tf is None:
        keras_home = keras_home_path()
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


def get_network_module(network_name):
    """Return the model module selected by the CLI."""
    try:
        return NETWORK_MODULES[network_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported network: {network_name}") from exc


def network_model_config(network_name):
    """Return the lightweight architecture signature for result reuse checks."""
    network_module = get_network_module(network_name)
    model_config = {}

    for attr_name in (
        "CONV1_FILTERS",
        "CONV2_FILTERS",
        "CONV3_FILTERS",
        "FC_UNITS",
        "FC1_UNITS",
        "FC2_UNITS",
    ):
        if hasattr(network_module, attr_name):
            model_config[attr_name.lower()] = int(getattr(network_module, attr_name))

    return model_config


def get_dataset_config(dataset_name):
    """Return dataset metadata selected by the CLI."""
    try:
        return DATASET_CONFIGS[dataset_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported dataset: {dataset_name}") from exc


def build_network_model_builder(network_name, dataset_config, qat=False):
    """Create the zero-argument model builder expected by FL strategies."""
    network_module = get_network_module(network_name)
    build_fn = network_module.build_qat_model if qat else network_module.build_model

    def model_builder():
        return build_fn(
            import_tensorflow(),
            input_shape=dataset_config.input_shape,
            num_classes=dataset_config.num_classes,
        )

    return model_builder


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
    """Create a simple IID partition of a dataset across clients."""
    rng = np.random.default_rng(seed)
    indices = np.arange(len(x))
    rng.shuffle(indices)
    shards = np.array_split(indices, num_clients)
    return [(x[idx], y[idx]) for idx in shards]


def apply_data_limits(x_train, y_train, x_test, y_test, train_limit, test_limit):
    """Apply optional train/test limits after preprocessing."""
    if train_limit is not None:
        x_train = x_train[:train_limit]
        y_train = y_train[:train_limit]
    if test_limit is not None:
        x_test = x_test[:test_limit]
        y_test = y_test[:test_limit]

    return x_train, y_train, x_test, y_test


def preprocess_image_data(x_train, y_train, x_test, y_test):
    """Normalize image tensors and flatten labels to int64."""
    x_train = x_train.astype(np.float32) / 255.0
    x_test = x_test.astype(np.float32) / 255.0
    y_train = y_train.reshape(-1).astype(np.int64)
    y_test = y_test.reshape(-1).astype(np.int64)
    return x_train, y_train, x_test, y_test


def load_cifar10_clients(num_clients, train_limit, test_limit, seed):
    """Load CIFAR-10, normalize images, and split train data by client."""
    (x_train, y_train), (x_test, y_test) = load_dataset_with_cache_retry(
        dataset_name="cifar10",
        cache_prefixes=("cifar-10-batches-py",),
        load_fn=tf.keras.datasets.cifar10.load_data,
    )
    x_train, y_train, x_test, y_test = preprocess_image_data(
        x_train,
        y_train,
        x_test,
        y_test,
    )
    x_train, y_train, x_test, y_test = apply_data_limits(
        x_train,
        y_train,
        x_test,
        y_test,
        train_limit,
        test_limit,
    )
    return split_iid(x_train, y_train, num_clients, seed), (x_test, y_test)


def load_mnist_clients(num_clients, train_limit, test_limit, seed):
    """Load MNIST, normalize images, add a channel, and split train data."""
    (x_train, y_train), (x_test, y_test) = load_dataset_with_cache_retry(
        dataset_name="mnist",
        cache_prefixes=("mnist.npz",),
        load_fn=tf.keras.datasets.mnist.load_data,
    )
    x_train, y_train, x_test, y_test = preprocess_image_data(
        x_train,
        y_train,
        x_test,
        y_test,
    )
    x_train = x_train[..., np.newaxis]
    x_test = x_test[..., np.newaxis]
    x_train, y_train, x_test, y_test = apply_data_limits(
        x_train,
        y_train,
        x_test,
        y_test,
        train_limit,
        test_limit,
    )
    return split_iid(x_train, y_train, num_clients, seed), (x_test, y_test)


def file_md5(path):
    """Return the MD5 hex digest for a local file."""
    digest = hashlib.md5()
    with Path(path).open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def organamnist_cache_message(cache_path):
    """Build a clear cache-preparation message for OrganAMNIST failures."""
    return (
        f"OrganAMNIST is required at {cache_path}. Run "
        "python3 fl/download_organamnist.py from the repository root, "
        f"or download {ORGANAMNIST_URL} manually and verify MD5 {ORGANAMNIST_MD5}."
    )


def ensure_organamnist_npz(repo_root):
    """Return a verified cached OrganAMNIST npz path."""
    cache_dir = repo_root / MEDMNIST_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / ORGANAMNIST_FILENAME

    if not cache_path.exists():
        raise FileNotFoundError(organamnist_cache_message(cache_path))

    actual_md5 = file_md5(cache_path)
    if actual_md5 != ORGANAMNIST_MD5:
        raise ValueError(
            f"{cache_path} has MD5 {actual_md5}; expected {ORGANAMNIST_MD5}. "
            "Run python3 fl/download_organamnist.py --force from the repository "
            "root to replace it."
        )

    return cache_path


def load_organamnist_split(npz_data, split):
    """Load one OrganAMNIST split from the cached npz file."""
    image_key = f"{split}_images"
    label_key = f"{split}_labels"
    try:
        return np.asarray(npz_data[image_key]), np.asarray(npz_data[label_key])
    except KeyError as exc:
        raise KeyError(
            f"{ORGANAMNIST_FILENAME} does not contain expected key {exc.args[0]!r}."
        ) from exc


def load_organamnist_clients(num_clients, train_limit, test_limit, seed):
    """Load OrganAMNIST, normalize images, add a channel, and split train data."""
    repo_root = Path(__file__).resolve().parents[1]
    with dataset_cache_lock("organamnist"):
        npz_path = ensure_organamnist_npz(repo_root)
        with np.load(npz_path) as npz_data:
            x_train, y_train = load_organamnist_split(npz_data, "train")
            x_test, y_test = load_organamnist_split(npz_data, "test")
    x_train, y_train, x_test, y_test = preprocess_image_data(
        x_train,
        y_train,
        x_test,
        y_test,
    )
    x_train = x_train[..., np.newaxis]
    x_test = x_test[..., np.newaxis]
    x_train, y_train, x_test, y_test = apply_data_limits(
        x_train,
        y_train,
        x_test,
        y_test,
        train_limit,
        test_limit,
    )
    return split_iid(x_train, y_train, num_clients, seed), (x_test, y_test)


def load_dataset_clients(dataset_name, num_clients, train_limit, test_limit, seed):
    """Load the selected dataset and return federated client shards."""
    if dataset_name == "cifar10":
        return load_cifar10_clients(num_clients, train_limit, test_limit, seed)
    if dataset_name == "mnist":
        return load_mnist_clients(num_clients, train_limit, test_limit, seed)
    if dataset_name == "organamnist":
        return load_organamnist_clients(num_clients, train_limit, test_limit, seed)

    raise ValueError(f"Unsupported dataset: {dataset_name}")


def build_framework_strategies(
    framework_name,
    network_name,
    dataset_config,
    heversa,
    protocol_config,
):
    """Build the comparison variants for the selected FL framework."""
    model_builder = build_network_model_builder(
        network_name=network_name,
        dataset_config=dataset_config,
        qat=framework_name == "fedavg_qat",
    )

    if framework_name == "fedavg":
        return build_fedavg_strategies(
            heversa=heversa,
            protocol_config=protocol_config,
            model_builder=model_builder,
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
            model_builder=model_builder,
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


def experiment_name_parts(dataset_name, network_name, rep_name=None, output_prefix=None):
    """Return stable filename parts shared by model and result outputs."""
    parts = []
    if output_prefix:
        parts.append(safe_name(output_prefix))
    parts.extend([safe_name(dataset_name), safe_name(network_name)])
    if rep_name:
        parts.append(safe_name(rep_name))
    return parts


def model_output_path(
    strategy_name,
    dataset_name,
    network_name,
    rep_name=None,
    output_prefix=None,
):
    """Derive the TFLite output path from the selected strategy."""
    experiment_name = "_".join(
        experiment_name_parts(dataset_name, network_name, rep_name, output_prefix)
    )
    return (
        MODEL_OUTPUT_DIR
        / f"{experiment_name}_{safe_name(strategy_name)}_int8.tflite"
    )


def results_output_path(
    strategy_names,
    dataset_name,
    network_name,
    rep_name=None,
    output_prefix=None,
):
    """Derive the JSON output path from the selected strategy comparison."""
    experiment_name = "_".join(
        experiment_name_parts(dataset_name, network_name, rep_name, output_prefix)
    )
    comparison_name = "_vs_".join(safe_name(name) for name in strategy_names)
    return RESULT_OUTPUT_DIR / f"{experiment_name}_{comparison_name}.json"


def expected_strategy_names(framework_name):
    """Return the strategy names written by a framework without building models."""
    try:
        return FRAMEWORK_STRATEGY_NAMES[framework_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported FL framework: {framework_name}") from exc


def expected_experiment_outputs(args):
    """Return the result and model paths for the requested experiment."""
    strategy_names = expected_strategy_names(args.fl_framework)
    result_path = results_output_path(
        strategy_names,
        args.dataset,
        args.network,
        rep_name=args.rep_name,
        output_prefix=args.output_prefix,
    )
    model_outputs = {
        name: model_output_path(
            name,
            args.dataset,
            args.network,
            rep_name=args.rep_name,
            output_prefix=args.output_prefix,
        )
        for name in strategy_names
    }
    return strategy_names, result_path, model_outputs


def expected_experiment_config(args, protocol_config=None):
    """Return the config keys that define whether outputs match this run."""
    if protocol_config is None:
        protocol_config = ProtocolConfig()

    return {
        "fl_framework": args.fl_framework,
        "dataset": args.dataset,
        "network": args.network,
        "model_config": network_model_config(args.network),
        "clients": protocol_config.num_clients,
        "threshold": protocol_config.threshold,
        "update_len": protocol_config.update_len,
        "rounds": args.rounds,
        "local_epochs": args.local_epochs,
        "batch_size": args.batch_size,
        "train_limit": args.train_limit,
        "test_limit": args.test_limit,
        "seed": args.seed,
        "rep_name": args.rep_name,
        "output_prefix": args.output_prefix,
        "quant_scale": protocol_config.quant_scale,
    }


def output_file_present(path):
    """Return True when an output file exists and is non-empty."""
    try:
        path = Path(path)
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def result_file_present(path, args):
    """Return True when the result JSON exists and matches this run config."""
    if not output_file_present(path):
        return False

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False

    actual_config = payload.get("config", {})
    expected_config = expected_experiment_config(args)
    return all(
        actual_config.get(key) == value for key, value in expected_config.items()
    )


def experiment_outputs_complete(args):
    """Return output completeness plus the expected result and model paths."""
    _, result_path, model_outputs = expected_experiment_outputs(args)
    if not result_file_present(result_path, args):
        return False, result_path, model_outputs

    models_present = all(output_file_present(path) for path in model_outputs.values())
    return models_present, result_path, model_outputs


def ensure_experiment_args(args):
    """Fill defaults expected by direct callers before output checks."""
    if not hasattr(args, "fl_framework"):
        args.fl_framework = "fedavg"
    if not hasattr(args, "dataset"):
        args.dataset = "cifar10"
    if not hasattr(args, "network"):
        args.network = "cnn"
    if not hasattr(args, "rounds"):
        args.rounds = 3
    if not hasattr(args, "local_epochs"):
        args.local_epochs = 1
    if not hasattr(args, "batch_size"):
        args.batch_size = 64
    if not hasattr(args, "train_limit"):
        args.train_limit = 8000
    if not hasattr(args, "test_limit"):
        args.test_limit = 2000
    if not hasattr(args, "seed"):
        args.seed = 26
    if not hasattr(args, "rep_name"):
        args.rep_name = None
    if not hasattr(args, "output_prefix") or not args.output_prefix:
        args.output_prefix = None


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
        "config": expected_experiment_config(args, protocol_config),
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
    ensure_experiment_args(args)
    complete, result_path, model_outputs = experiment_outputs_complete(args)
    if complete:
        experiment_label = f"{args.dataset} {args.network} {args.fl_framework}"
        if args.output_prefix:
            experiment_label = f"{args.output_prefix} {experiment_label}"
        if args.rep_name:
            experiment_label = f"{experiment_label} {args.rep_name}"
        print(f"skipping completed experiment: {experiment_label}", flush=True)
        print(f"existing results: {result_path}", flush=True)
        for name, output_path in model_outputs.items():
            print(f"existing {name} model: {output_path}", flush=True)
        return

    repo_root = Path(__file__).resolve().parents[1]
    heversa = import_heversa(repo_root)
    protocol_config = ProtocolConfig()
    dataset_config = get_dataset_config(args.dataset)
    load_data_before_tensorflow = args.dataset == "organamnist"

    if load_data_before_tensorflow:
        client_data, test_data = load_dataset_clients(
            dataset_name=args.dataset,
            num_clients=protocol_config.num_clients,
            train_limit=args.train_limit,
            test_limit=args.test_limit,
            seed=args.seed,
        )

    import_tensorflow()
    set_random_seed(args.seed)

    if not load_data_before_tensorflow:
        client_data, test_data = load_dataset_clients(
            dataset_name=args.dataset,
            num_clients=protocol_config.num_clients,
            train_limit=args.train_limit,
            test_limit=args.test_limit,
            seed=args.seed,
        )

    strategies = build_framework_strategies(
        framework_name=args.fl_framework,
        network_name=args.network,
        dataset_config=dataset_config,
        heversa=heversa,
        protocol_config=protocol_config,
    )

    seed_model = strategies[0].create_model()
    initial_weights = seed_model.get_weights()
    initial_flat, _, _ = flatten_weights(initial_weights)
    tf.keras.backend.clear_session()

    print(
        f"Starting {dataset_config.display_name} "
        f"{args.network} {args.fl_framework} comparison"
    )
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
        result.name: str(
            model_output_path(
                result.name,
                args.dataset,
                args.network,
                rep_name=args.rep_name,
                output_prefix=args.output_prefix,
            )
        )
        for result in results
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
        results_output_path(
            strategy_names,
            args.dataset,
            args.network,
            rep_name=args.rep_name,
            output_prefix=args.output_prefix,
        ),
        add_framework_config(args.fl_framework, payload),
    )


def optional_int(value):
    """Parse an optional integer CLI value, accepting none/null for no limit."""
    if value is None:
        return None

    normalized = str(value).strip().lower()
    if normalized in ("none", "null", ""):
        return None

    return int(value)


def parse_args():
    parser = argparse.ArgumentParser(
        description="FL comparison with optional HeVerSa aggregation."
    )
    parser.add_argument(
        "--fl-framework",
        choices=SUPPORTED_FL_FRAMEWORKS,
        default="fedavg",
    )
    parser.add_argument(
        "--dataset",
        choices=SUPPORTED_DATASETS,
        default="cifar10",
    )
    parser.add_argument(
        "--network",
        choices=SUPPORTED_NETWORKS,
        default="cnn",
    )
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--local-epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--train-limit", type=optional_int, default=8000)
    parser.add_argument("--test-limit", type=optional_int, default=2000)
    parser.add_argument("--seed", type=int, default=26)
    parser.add_argument("--rep-name", default=None)
    parser.add_argument("--output-prefix", default=None)
    parser.add_argument("--eval-tflite", action="store_true")
    return parser.parse_args()


def main():
    train(parse_args())


if __name__ == "__main__":
    main()
