#!/bin/bash
# set -x
thread_num=$1
process_id=$2
num_of_ops=$3

PREFIX_PATH="/home/gxr/mongodb-run/ebpf_monitor"
current=`date "+%Y-%m-%d-%H-%M-%S"`
OUTPUT_PATH=${PREFIX_PATH}/lock_flow_log/${current}.analysis.${thread_num}.threads.${num_of_ops}.ops
mkdir -p $OUTPUT_PATH

cmd_path="$PREFIX_PATH/src/lock_flow_analysis_ctrl_signal.py"

# tid_output=$(ps -T -p $process_id) 
# comm_array=($(echo "$tid_output" | awk 'NR>1 {print $5}'))
# filtered_comm_array=($(printf "%s\n" "${comm_array[@]}" | grep 'conn'))
  
filtered_comm_array=()
for ((i=1; i<=thread_num; i++))
do
    filtered_comm_array+=("conn$i")
done
echo "${filtered_comm_array[@]}"

pids=$(sudo lsof /sys/kernel/debug/tracing/trace_pipe | awk 'NR>1 {print $2}')
if [ ! -z "$pids" ]; then
    echo "Killing existing processes using trace_pipe: $pids"
    sudo kill -9 $pids
fi

echo "${comm_array[@]}"
# output_file=${OUTPUT_PATH}/trace_locks.${thread_num}.threads.log
sudo python3 $cmd_path "${filtered_comm_array[@]}" "$OUTPUT_PATH" 