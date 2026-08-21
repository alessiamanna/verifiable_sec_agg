#!/bin/bash

set -euo pipefail

# Submit one Slurm job for each dataset/network/repetition QAT run.

if [[ -n "${SLURM_SUBMIT_DIR:-}" && -f "${SLURM_SUBMIT_DIR}/launch_fl_heversa.sh" ]]; then
  SCRIPT_DIR="$(cd "${SLURM_SUBMIT_DIR}" && pwd)"
elif [[ -n "${SLURM_SUBMIT_DIR:-}" && -f "${SLURM_SUBMIT_DIR}/fl/launch_fl_heversa.sh" ]]; then
  SCRIPT_DIR="$(cd "${SLURM_SUBMIT_DIR}/fl" && pwd)"
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONDA_SH="/home/SOFTWARE/miniforge3/etc/profile.d/conda.sh"
CONDA_ENV="heversa310"
HEVERSA_BUILD_DIR="${REPO_ROOT}/build-linux"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOG_DIR}"

# Experiment size. Edit these values for smoke tests or longer runs.
ROUNDS=50
LOCAL_EPOCHS=3
BATCH_SIZE=64
TRAIN_LIMIT=None
TEST_LIMIT=None
OUTPUT_PREFIX="trial2"

DATASETS=(
  cifar10
  mnist
  organamnist
)

NETWORKS=(
  cnn_medium
  mlp_medium
)

REPETITIONS=(
  rep0:0
  rep1:1
  rep2:2
)

for dataset in "${DATASETS[@]}"; do
  for network in "${NETWORKS[@]}"; do
    for repetition in "${REPETITIONS[@]}"; do
      rep_name="${repetition%%:*}"
      seed="${repetition##*:}"
      job_name="${dataset}_${network}_qat_${rep_name}"
      log_path="${LOG_DIR}/${job_name}_%j.out"
      output_prefix_arg=""
      if [[ -n "${OUTPUT_PREFIX}" ]]; then
        output_prefix_arg=" --output-prefix ${OUTPUT_PREFIX}"
      fi

      sbatch \
        --job-name="${job_name}" \
        --partition=ingnormal \
        --gres=gpu:1 \
        --time=8-00:00:00 \
        --output="${log_path}" \
        --error="${log_path}" \
        --chdir="${REPO_ROOT}" \
        --wrap="bash -lc 'source ${CONDA_SH} && conda activate ${CONDA_ENV} && export PYTHONPATH=${HEVERSA_BUILD_DIR}:\${PYTHONPATH:-} && python3 fl/fl_heversa.py --fl-framework fedavg_qat --dataset ${dataset} --network ${network} --seed ${seed} --rep-name ${rep_name} --rounds ${ROUNDS} --local-epochs ${LOCAL_EPOCHS} --batch-size ${BATCH_SIZE} --train-limit ${TRAIN_LIMIT} --test-limit ${TEST_LIMIT}${output_prefix_arg}'"
    done
  done
done
