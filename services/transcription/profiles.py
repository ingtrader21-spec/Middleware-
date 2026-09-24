from dataclasses import dataclass


@dataclass(frozen=True)
class ModelProfile:
    model: str
    compute_type: str
    device: str
    concurrency: int
    live: bool


CPU_STAGING = ModelProfile("small", "int8", "cpu", 1, False)
GPU_LIVE = ModelProfile("distil-large-v3", "float16", "cuda", 2, True)
GPU_FINAL = ModelProfile("large-v3", "float16", "cuda", 1, False)
