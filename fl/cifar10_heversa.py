try:
    from .fl_heversa import *  # noqa: F401,F403
    from . import fl_heversa as _base
except ImportError:
    from fl_heversa import *  # noqa: F401,F403
    import fl_heversa as _base


def train(args):
    """Compatibility entry point for the old CIFAR-10-specific script name."""
    return _base.train(args)


def parse_args():
    return _base.parse_args()


def main():
    train(parse_args())


if __name__ == "__main__":
    main()
