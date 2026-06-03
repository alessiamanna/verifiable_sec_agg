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

# Slightly larger than the old 16-unit MLP, but still compact enough for edge FL.
# Input size is 32 * 32 * 3 = 3072, so the first dense layer dominates params.
FC1_UNITS = 128
FC2_UNITS = 64


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
    """Build a compact 2-hidden-layer MLP for CIFAR-10."""
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=input_shape, name="image"),
            tf.keras.layers.Flatten(name="flatten"),
            tf.keras.layers.Dense(FC1_UNITS, activation="relu", name="fc1"),
            tf.keras.layers.Dense(FC2_UNITS, activation="relu", name="fc2"),
            tf.keras.layers.Dense(num_classes, activation="softmax", name="fc3"),
        ],
        name="classifier_mlp_medium",
    )
    return compile_classifier(tf, model)


def build_qat_model(
    tf,
    input_shape=DEFAULT_INPUT_SHAPE,
    num_classes=DEFAULT_NUM_CLASSES,
):
    """Build the same compact MLP with fake quantization in the training graph."""
    FixedRangeFakeQuant, _, FakeQuantDense = get_qat_layer_classes(tf)

    inputs = tf.keras.layers.Input(shape=input_shape, name="image")
    x = FixedRangeFakeQuant(
        INPUT_QUANT_MIN,
        INPUT_QUANT_MAX,
        name="input_fake_quant",
    )(inputs)
    x = tf.keras.layers.Flatten(name="flatten")(x)
    x = FakeQuantDense(
        FC1_UNITS,
        activation=tf.nn.relu6,
        output_min=ACTIVATION_QUANT_MIN,
        output_max=ACTIVATION_QUANT_MAX,
        name="fc1",
    )(x)
    x = FakeQuantDense(
        FC2_UNITS,
        activation=tf.nn.relu6,
        output_min=ACTIVATION_QUANT_MIN,
        output_max=ACTIVATION_QUANT_MAX,
        name="fc2",
    )(x)
    x = FakeQuantDense(
        num_classes,
        output_min=LOGIT_QUANT_MIN,
        output_max=LOGIT_QUANT_MAX,
        name="fc3_logits",
    )(x)
    outputs = tf.keras.layers.Activation("softmax", name="probabilities")(x)

    model = tf.keras.Model(inputs=inputs, outputs=outputs, name="classifier_qat_mlp_medium")
    return compile_classifier(tf, model)


def build_cifar10_mlp(tf):
    return build_model(tf)


def build_cifar10_qat_mlp(tf):
    return build_qat_model(tf)
