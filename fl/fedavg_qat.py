try:
    from . import fl_heversa as base
    from . import cnn
    from .fedavg import (
        FedAvgHeVersaStrategy,
        FedAvgPlainStrategy,
    )
    from .qat_layers import (
        ACTIVATION_QUANT_MAX,
        ACTIVATION_QUANT_MIN,
        INPUT_QUANT_MAX,
        INPUT_QUANT_MIN,
        LOGIT_QUANT_MAX,
        LOGIT_QUANT_MIN,
        QAT_NUM_BITS,
        WEIGHT_QUANT_MAX,
        WEIGHT_QUANT_MIN,
    )
except ImportError:
    import fl_heversa as base
    import cnn
    from fedavg import (
        FedAvgHeVersaStrategy,
        FedAvgPlainStrategy,
    )
    from qat_layers import (
        ACTIVATION_QUANT_MAX,
        ACTIVATION_QUANT_MIN,
        INPUT_QUANT_MAX,
        INPUT_QUANT_MIN,
        LOGIT_QUANT_MAX,
        LOGIT_QUANT_MIN,
        QAT_NUM_BITS,
        WEIGHT_QUANT_MAX,
        WEIGHT_QUANT_MIN,
    )


QAT_PLAIN_STRATEGY_NAME = "fedavg_qat_plain"
QAT_HEVERSA_STRATEGY_NAME = "fedavg_qat_heversa"


def default_model_builder():
    """Build the default QAT CNN for direct fedavg_qat.py entry points."""
    tf = base.import_tensorflow()
    return cnn.build_qat_model(tf)


def build_strategies(
    heversa,
    protocol_config,
    clear_session=None,
    keras_verbose=None,
    model_builder=None,
):
    """Return QAT FedAvg variants with plain and HeVerSa aggregation."""
    tf = base.import_tensorflow()
    if clear_session is None:
        clear_session = tf.keras.backend.clear_session
    if keras_verbose is None:
        keras_verbose = base.KERAS_VERBOSE
    if model_builder is None:
        model_builder = default_model_builder

    return [
        FedAvgPlainStrategy(
            model_builder=model_builder,
            clear_session=clear_session,
            keras_verbose=keras_verbose,
            name=QAT_PLAIN_STRATEGY_NAME,
        ),
        FedAvgHeVersaStrategy(
            heversa=heversa,
            protocol_config=protocol_config,
            model_builder=model_builder,
            clear_session=clear_session,
            keras_verbose=keras_verbose,
            name=QAT_HEVERSA_STRATEGY_NAME,
        ),
    ]


def build_qat_heversa_strategy(heversa, protocol_config, model_builder=None):
    """Build only the HeVerSa QAT strategy for small direct experiments."""
    return build_strategies(heversa, protocol_config, model_builder=model_builder)[1]


def add_qat_config(payload):
    """Record the fake-quant ranges next to the experiment metrics."""
    payload["config"].update(
        {
            "qat": True,
            "qat_num_bits": QAT_NUM_BITS,
            "input_quant_range": [INPUT_QUANT_MIN, INPUT_QUANT_MAX],
            "activation_quant_range": [
                ACTIVATION_QUANT_MIN,
                ACTIVATION_QUANT_MAX,
            ],
            "weight_quant_range": [WEIGHT_QUANT_MIN, WEIGHT_QUANT_MAX],
            "logit_quant_range": [LOGIT_QUANT_MIN, LOGIT_QUANT_MAX],
        }
    )
    return payload


def train(args):
    args.fl_framework = "fedavg_qat"
    base.train(args)


def parse_args():
    args = base.parse_args()
    args.fl_framework = "fedavg_qat"
    return args


def main():
    train(parse_args())


if __name__ == "__main__":
    main()
