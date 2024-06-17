#!/bin/bash
# set -x
perf_time=$1
process_id=$2
PREFIX_PATH="/home/gxr/mongodb-run/ebpf_monitor"
current=`date "+%Y-%m-%d-%H-%M-%S"`
cmd_path="$PREFIX_PATH/bcc_trace_locks.py"

tid_output=$(ps -T -p $process_id) 

echo "$tid_output"

tid_array=($(echo "$tid_output" | awk 'NR>1 {print $2}'))

comm_array=($(echo "$tid_output" | awk 'NR>1 {print $5}'))

OUTPUT_PATH=${PREFIX_PATH}/locks_analysis_log/${current}

mkdir -p $OUTPUT_PATH


len=${#tid_array[@]}

for ((i=8; i<len; i++)); do
        tid="${tid_array[i]}"
        comm_name="${comm_array[i]}"
        output_file=${OUTPUT_PATH}/bcc_trace_locks.${perf_time}.${tid}.${comm_name}.log
        echo "$output_file"
        echo "$cmd_path"
        sudo python $cmd_path --time=$perf_time --pid=$tid 2>&1 | tee -a ${output_file}
done



