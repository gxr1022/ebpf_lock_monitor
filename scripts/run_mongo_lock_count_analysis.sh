#!/bin/bash
# set -x
perf_time=$1
process_id=$2
PREFIX_PATH="/home/gxr/mongodb-run/ebpf_monitor"
current=`date "+%Y-%m-%d-%H-%M-%S"`
cmd_path="$PREFIX_PATH/src/mongo_lock_count_analysis.py"

tid_output=$(ps -T -p $process_id) 

echo "$tid_output"

comm_array=($(echo "$tid_output" | awk 'NR>1 {print $5}'))

OUTPUT_PATH=${PREFIX_PATH}/locks_analysis_log/${current}.analysis

mkdir -p $OUTPUT_PATH

len=${#comm_array[@]}

for ((i=47; i<len; i++)); do
        comm_name="${comm_array[i]}"
        output_file=${OUTPUT_PATH}/trace_locks.${perf_time}.${process_id}.${comm_name}.log
        echo "$output_file"
        echo "$cmd_path"
        sudo python $cmd_path  $comm_name  $perf_time  2>&1 | tee -a ${output_file}
done



