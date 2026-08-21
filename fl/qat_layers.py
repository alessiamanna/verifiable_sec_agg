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


def get_qat_layer_classes(tf):
    """Create fake-quant Keras layer classes after TensorFlow is available."""
    global _QAT_LAYER_CLASSES

    if _QAT_LAYER_CLASSES is not None:
        return _QAT_LAYER_CLASSES

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
