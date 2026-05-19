try:
    from . import cifar10_heversa as base
    from .fedavg import (
        FedAvgHeVersaStrategy,
        FedAvgPlainStrategy,
    )
except ImportError:
    import cifar10_heversa as base
    from fedavg import (
        FedAvgHeVersaStrategy,
        FedAvgPlainStrategy,
    )


QAT_PLAIN_STRATEGY_NAME = "fedavg_qat_plain"
QAT_HEVERSA_STRATEGY_NAME = "fedavg_qat_heversa"

# Fixed fake-quant ranges used during local client training. The ranges are
# intentionally conservative for this small ReLU6 CNN so the int8 TFLite export
# sees the same clipping/rounding behavior during training.
INPUT_QUANT_MIN = 0.0
INPUT_QUANT_MAX = 1.0
ACTIVATION_QUANT_MIN = 0.0
ACTIVATION_QUANT_MAX = 6.0
WEIGHT_QUANT_MIN = -1.0
WEIGHT_QUANT_MAX = 1.0
LOGIT_QUANT_MIN = -8.0
LOGIT_QUANT_MAX = 8.0
QAT_NUM_BITS = 8

_QAT_LAYER_CLASSES = None


def get_qat_layer_classes():
    """Create fake-quant Keras layer classes after TensorFlow is available."""
    global _QAT_LAYER_CLASSES

    if _QAT_LAYER_CLASSES is not None:
        return _QAT_LAYER_CLASSES

    tf = base.import_tensorflow()

    def fake_quant_tensor(tensor, min_value, max_value, narrow_range=False):
        return tf.quantization.fake_quant_with_min_max_vars(
            tensor,
            tf.cast(min_value, tensor.dtype),
            tf.cast(max_value, tensor.dtype),
            num_bits=QAT_NUM_BITS,
            narrow_range=narrow_range,
        )

    @tf.keras.utils.register_keras_serializable(package="HeVerSa")
    class FixedRangeFakeQuant(tf.keras.layers.Layer):
        """Fake-quantize activations with a fixed int8 range."""

        def __init__(
            self,
            min_value,
            max_value,
            narrow_range=False,
            **kwargs,
        ):
            super().__init__(**kwargs)
            self.min_value = float(min_value)
            self.max_value = float(max_value)
            self.narrow_range = bool(narrow_range)

        def call(self, inputs, training=None):
            return fake_quant_tensor(
                inputs,
                self.min_value,
                self.max_value,
                narrow_range=self.narrow_range,
            )

        def get_config(self):
            config = super().get_config()
            config.update(
                {
                    "min_value": self.min_value,
                    "max_value": self.max_value,
                    "narrow_range": self.narrow_range,
                }
            )
            return config

    @tf.keras.utils.register_keras_serializable(package="HeVerSa")
    class FakeQuantConv2D(tf.keras.layers.Conv2D):
        """Conv2D with fake-quantized weights and output activations."""

        def __init__(
            self,
            *args,
            weight_min=WEIGHT_QUANT_MIN,
            weight_max=WEIGHT_QUANT_MAX,
            output_min=ACTIVATION_QUANT_MIN,
            output_max=ACTIVATION_QUANT_MAX,
            **kwargs,
        ):
            super().__init__(*args, **kwargs)
            self.weight_min = float(weight_min)
            self.weight_max = float(weight_max)
            self.output_min = float(output_min)
            self.output_max = float(output_max)

        def call(self, inputs):
            kernel = fake_quant_tensor(
                self.kernel,
                self.weight_min,
                self.weight_max,
                narrow_range=True,
            )

            if hasattr(self, "convolution_op"):
                outputs = self.convolution_op(inputs, kernel)
            else:
                outputs = tf.keras.backend.conv2d(
                    inputs,
                    kernel,
                    strides=self.strides,
                    padding=self.padding,
                    data_format=self.data_format,
                    dilation_rate=self.dilation_rate,
                )

            if self.use_bias:
                data_format = "NCHW" if self.data_format == "channels_first" else "NHWC"
                outputs = tf.nn.bias_add(outputs, self.bias, data_format=data_format)

            if self.activation is not None:
                outputs = self.activation(outputs)

            return fake_quant_tensor(
                outputs,
                self.output_min,
                self.output_max,
                narrow_range=False,
            )

        def get_config(self):
            config = super().get_config()
            config.update(
                {
                    "weight_min": self.weight_min,
                    "weight_max": self.weight_max,
                    "output_min": self.output_min,
                    "output_max": self.output_max,
                }
            )
            return config

    @tf.keras.utils.register_keras_serializable(package="HeVerSa")
    class FakeQuantDense(tf.keras.layers.Dense):
        """Dense layer with fake-quantized weights and optional output range."""

        def __init__(
            self,
            *args,
            weight_min=WEIGHT_QUANT_MIN,
            weight_max=WEIGHT_QUANT_MAX,
            output_min=None,
            output_max=None,
            **kwargs,
        ):
            super().__init__(*args, **kwargs)
            self.weight_min = float(weight_min)
            self.weight_max = float(weight_max)
            self.output_min = None if output_min is None else float(output_min)
            self.output_max = None if output_max is None else float(output_max)

        def call(self, inputs):
            kernel = fake_quant_tensor(
                self.kernel,
                self.weight_min,
                self.weight_max,
                narrow_range=True,
            )
            outputs = tf.linalg.matmul(inputs, kernel)

            if self.use_bias:
                outputs = tf.nn.bias_add(outputs, self.bias)

            if self.activation is not None:
                outputs = self.activation(outputs)

            if self.output_min is not None and self.output_max is not None:
                outputs = fake_quant_tensor(
                    outputs,
                    self.output_min,
                    self.output_max,
                    narrow_range=False,
                )

            return outputs

        def get_config(self):
            config = super().get_config()
            config.update(
                {
                    "weight_min": self.weight_min,
                    "weight_max": self.weight_max,
                    "output_min": self.output_min,
                    "output_max": self.output_max,
                }
            )
            return config

    _QAT_LAYER_CLASSES = FixedRangeFakeQuant, FakeQuantConv2D, FakeQuantDense
    return _QAT_LAYER_CLASSES


def build_cifar10_qat_cnn():
    """Build the CIFAR-10 CNN with fake quantization in the training graph."""
    tf = base.import_tensorflow()
    FixedRangeFakeQuant, FakeQuantConv2D, FakeQuantDense = get_qat_layer_classes()

    inputs = tf.keras.layers.Input(shape=(32, 32, 3), name="image")
    x = FixedRangeFakeQuant(
        INPUT_QUANT_MIN,
        INPUT_QUANT_MAX,
        name="input_fake_quant",
    )(inputs)
    x = FakeQuantConv2D(
        8,
        3,
        padding="same",
        activation=tf.nn.relu6,
        name="conv1",
    )(x)
    x = tf.keras.layers.MaxPooling2D(name="pool1")(x)
    x = FixedRangeFakeQuant(
        ACTIVATION_QUANT_MIN,
        ACTIVATION_QUANT_MAX,
        name="pool1_fake_quant",
    )(x)
    x = FakeQuantConv2D(
        16,
        3,
        padding="same",
        activation=tf.nn.relu6,
        name="conv2",
    )(x)
    x = tf.keras.layers.GlobalAveragePooling2D(name="global_average")(x)
    x = FixedRangeFakeQuant(
        ACTIVATION_QUANT_MIN,
        ACTIVATION_QUANT_MAX,
        name="global_average_fake_quant",
    )(x)
    x = FakeQuantDense(
        10,
        output_min=LOGIT_QUANT_MIN,
        output_max=LOGIT_QUANT_MAX,
        name="logits",
    )(x)
    outputs = tf.keras.layers.Activation("softmax", name="probabilities")(x)

    model = tf.keras.Model(inputs=inputs, outputs=outputs, name="cifar10_qat_cnn")
    model.compile(
        optimizer=tf.keras.optimizers.Adam(),
        loss=tf.keras.losses.SparseCategoricalCrossentropy(),
        metrics=["accuracy"],
    )
    return model


def build_strategies(heversa, protocol_config, clear_session=None, keras_verbose=None):
    """Return QAT FedAvg variants with plain and HeVerSa aggregation."""
    tf = base.import_tensorflow()
    if clear_session is None:
        clear_session = tf.keras.backend.clear_session
    if keras_verbose is None:
        keras_verbose = base.KERAS_VERBOSE

    return [
        FedAvgPlainStrategy(
            model_builder=build_cifar10_qat_cnn,
            clear_session=clear_session,
            keras_verbose=keras_verbose,
            name=QAT_PLAIN_STRATEGY_NAME,
        ),
        FedAvgHeVersaStrategy(
            heversa=heversa,
            protocol_config=protocol_config,
            model_builder=build_cifar10_qat_cnn,
            clear_session=clear_session,
            keras_verbose=keras_verbose,
            name=QAT_HEVERSA_STRATEGY_NAME,
        ),
    ]


def build_qat_heversa_strategy(heversa, protocol_config):
    """Build only the HeVerSa QAT strategy for small direct experiments."""
    return build_strategies(heversa, protocol_config)[1]


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
