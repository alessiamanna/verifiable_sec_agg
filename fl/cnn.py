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
CONV1_FILTERS = 8
CONV2_FILTERS = 16
FC_UNITS = 32


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
    """Build a small CNN with 2 convolutional layers and 2 FC layers."""
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=input_shape, name="image"),
            tf.keras.layers.Conv2D(
                CONV1_FILTERS,
                3,
                padding="same",
                activation="relu",
                name="conv1",
            ),
            tf.keras.layers.MaxPooling2D(name="pool1"),
            tf.keras.layers.Conv2D(
                CONV2_FILTERS,
                3,
                padding="same",
                activation="relu",
                name="conv2",
            ),
            tf.keras.layers.GlobalAveragePooling2D(name="global_average"),
            tf.keras.layers.Dense(FC_UNITS, activation="relu", name="fc1"),
            tf.keras.layers.Dense(num_classes, activation="softmax", name="fc2"),
        ],
        name="classifier_cnn",
    )
    return compile_classifier(tf, model)


def build_qat_model(
    tf,
    input_shape=DEFAULT_INPUT_SHAPE,
    num_classes=DEFAULT_NUM_CLASSES,
):
    """Build the same CNN with fake quantization in the training graph."""
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
        CONV2_FILTERS,
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

    model = tf.keras.Model(inputs=inputs, outputs=outputs, name="classifier_qat_cnn")
    return compile_classifier(tf, model)


def build_cifar10_cnn(tf):
    return build_model(tf)


def build_cifar10_qat_cnn(tf):
    return build_qat_model(tf)
