try:
    from .qat_layers import (
        ACTIVATION_QUANT_MAX,
        ACTIVATION_QUANT_MIN,
        INPUT_QUANT_MAX,
        INPUT_QUANT_MIN,
        LOGIT_QUANT_MAX,
        LOGIT_QUANT_MIN,
        get_qat_layer_classes,
    )
except ImportError:
    from qat_layers import (
        ACTIVATION_QUANT_MAX,
        ACTIVATION_QUANT_MIN,
        INPUT_QUANT_MAX,
        INPUT_QUANT_MIN,
        LOGIT_QUANT_MAX,
        LOGIT_QUANT_MIN,
        get_qat_layer_classes,
    )


DEFAULT_INPUT_SHAPE = (32, 32, 3)
DEFAULT_NUM_CLASSES = 10

# Still small, but much more suitable for CIFAR-10 than 8/16 filters.
# Approximate parameter count: ~25k parameters.
CONV1_FILTERS = 16
CONV2_FILTERS = 32
CONV3_FILTERS = 64
FC_UNITS = 64


def compile_classifier(tf, model):
    model.compile(
        optimizer=tf.keras.optimizers.Adam(),
        loss=tf.keras.losses.SparseCategoricalCrossentropy(),
        metrics=["accuracy"],
    )
    return model


def build_model(
    tf,
    input_shape=DEFAULT_INPUT_SHAPE,
    num_classes=DEFAULT_NUM_CLASSES,
):
    """Build a compact CIFAR-10 CNN.

    Compared with the tiny 8/16-filter model, this adds one convolutional
    stage and uses 16/32/64 filters. GlobalAveragePooling keeps the dense
    part small, so the model is still lightweight for edge experiments.
    """
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=input_shape, name="image"),

            tf.keras.layers.Conv2D(
                CONV1_FILTERS,
                3,
                padding="same",
                use_bias=False,
                name="conv1",
            ),
            tf.keras.layers.BatchNormalization(name="bn1"),
            tf.keras.layers.Activation("relu", name="relu1"),
            tf.keras.layers.MaxPooling2D(name="pool1"),

            tf.keras.layers.Conv2D(
                CONV2_FILTERS,
                3,
                padding="same",
                use_bias=False,
                name="conv2",
            ),
            tf.keras.layers.BatchNormalization(name="bn2"),
            tf.keras.layers.Activation("relu", name="relu2"),
            tf.keras.layers.MaxPooling2D(name="pool2"),

            tf.keras.layers.Conv2D(
                CONV3_FILTERS,
                3,
                padding="same",
                use_bias=False,
                name="conv3",
            ),
            tf.keras.layers.BatchNormalization(name="bn3"),
            tf.keras.layers.Activation("relu", name="relu3"),

            tf.keras.layers.GlobalAveragePooling2D(name="global_average"),
            tf.keras.layers.Dense(FC_UNITS, activation="relu", name="fc1"),
            tf.keras.layers.Dense(num_classes, activation="softmax", name="fc2"),
        ],
        name="classifier_cnn_medium",
    )
    return compile_classifier(tf, model)


def build_qat_model(
    tf,
    input_shape=DEFAULT_INPUT_SHAPE,
    num_classes=DEFAULT_NUM_CLASSES,
):
    """Build the compact CIFAR-10 CNN with fake quantization.

    This keeps the QAT style used in your existing model. BatchNorm layers are
    left as normal Keras layers; they are typically folded into Conv2D during
    TFLite conversion when possible.
    """
    FixedRangeFakeQuant, FakeQuantConv2D, FakeQuantDense = get_qat_layer_classes(tf)

    inputs = tf.keras.layers.Input(shape=input_shape, name="image")
    x = FixedRangeFakeQuant(
        INPUT_QUANT_MIN,
        INPUT_QUANT_MAX,
        name="input_fake_quant",
    )(inputs)

    x = FakeQuantConv2D(
        CONV1_FILTERS,
        3,
        padding="same",
        use_bias=False,
        name="conv1",
    )(x)
    x = tf.keras.layers.BatchNormalization(name="bn1")(x)
    x = tf.keras.layers.Activation(tf.nn.relu6, name="relu1")(x)
    x = tf.keras.layers.MaxPooling2D(name="pool1")(x)
    x = FixedRangeFakeQuant(
        ACTIVATION_QUANT_MIN,
        ACTIVATION_QUANT_MAX,
        name="pool1_fake_quant",
    )(x)

    x = FakeQuantConv2D(
        CONV2_FILTERS,
        3,
        padding="same",
        use_bias=False,
        name="conv2",
    )(x)
    x = tf.keras.layers.BatchNormalization(name="bn2")(x)
    x = tf.keras.layers.Activation(tf.nn.relu6, name="relu2")(x)
    x = tf.keras.layers.MaxPooling2D(name="pool2")(x)
    x = FixedRangeFakeQuant(
        ACTIVATION_QUANT_MIN,
        ACTIVATION_QUANT_MAX,
        name="pool2_fake_quant",
    )(x)

    x = FakeQuantConv2D(
        CONV3_FILTERS,
        3,
        padding="same",
        use_bias=False,
        name="conv3",
    )(x)
    x = tf.keras.layers.BatchNormalization(name="bn3")(x)
    x = tf.keras.layers.Activation(tf.nn.relu6, name="relu3")(x)
    x = FixedRangeFakeQuant(
        ACTIVATION_QUANT_MIN,
        ACTIVATION_QUANT_MAX,
        name="conv3_fake_quant",
    )(x)

    x = tf.keras.layers.GlobalAveragePooling2D(name="global_average")(x)
    x = FixedRangeFakeQuant(
        ACTIVATION_QUANT_MIN,
        ACTIVATION_QUANT_MAX,
        name="global_average_fake_quant",
    )(x)

    x = FakeQuantDense(
        FC_UNITS,
        activation=tf.nn.relu6,
        output_min=ACTIVATION_QUANT_MIN,
        output_max=ACTIVATION_QUANT_MAX,
        name="fc1",
    )(x)
    x = FakeQuantDense(
        num_classes,
        output_min=LOGIT_QUANT_MIN,
        output_max=LOGIT_QUANT_MAX,
        name="fc2_logits",
    )(x)
    outputs = tf.keras.layers.Activation("softmax", name="probabilities")(x)

    model = tf.keras.Model(
        inputs=inputs,
        outputs=outputs,
        name="classifier_qat_cnn_medium",
    )
    return compile_classifier(tf, model)


def build_cifar10_cnn(tf):
    return build_model(tf)


def build_cifar10_qat_cnn(tf):
    return build_qat_model(tf)
