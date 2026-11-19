from enum import Enum


class DistributionChannel(str, Enum):
    STABLE = "stable"
    BETA = "beta"
    ALPHA = "alpha"
    EXPERIMENTAL = "experimental"
    DEVELOPMENT = "development"
