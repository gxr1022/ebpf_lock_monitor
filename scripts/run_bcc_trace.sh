#!/bin/bash
set -x
perf_time=$1
process_id=$2
PREFIX_PATH="/home/gxr/mongodb-run/ebpf_monitor"
current=`date "+%Y-%m-%d-%H-%M-%S"`
cmd_path="$PREFIX_PATH/bcc_trace_locks.py"

OUTPUT_PATH=${PREFIX_PATH}/locks_analysis_log/${current}

mkdir -p $OUTPUT_PATH

outputh_file=${OUTPUT_PATH}/bcc_trace_locks.${perf_time}.${process_id}.log


sudo python $cmd_path --time=$perf_time --pid=$process_id 2>&1 | tee -a ${outputh_file}

