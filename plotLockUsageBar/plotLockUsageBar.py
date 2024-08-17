import os
import pandas as pd
import matplotlib.pyplot as plt

base_dir = "/home/gxr/mongodb-run/ebpf_monitor/data/output_lock_usage_type"
all_data = pd.DataFrame()

for root, dirs, files in os.walk(base_dir):
    for file in files:
        if file == "lock_usage_by_type.csv":
            file_path = os.path.join(root, file)
            df = pd.read_csv(file_path)
            ops_value = int(os.path.basename(root).split('.')[4].replace("threads", ""))
            df['ops'] = ops_value
            all_data = pd.concat([all_data, df], ignore_index=True)

lock_data = all_data.pivot_table(index='ops', columns='Lock Type', values='Lock Count', aggfunc='sum').fillna(0)
unlock_data = all_data.pivot_table(index='ops', columns='Lock Type', values='Unlock Count', aggfunc='sum').fillna(0)

fig, ax = plt.subplots(figsize=(14, 8))

lock_data.plot(kind='bar', stacked=True, ax=ax, position=0, width=0.4, color=['skyblue', 'orange', 'green', 'red', 'purple'])
unlock_data.plot(kind='bar', stacked=True, ax=ax, position=1, width=0.4, alpha=0.7, hatch='//', color=['skyblue', 'orange', 'green', 'red', 'purple'])

ax.set_title('Lock and Unlock Counts by Lock Type and ops')
ax.set_xlabel('ops')
ax.set_ylabel('Count')

ax.legend(title='Lock Type', loc='upper left', bbox_to_anchor=(1, 1))

output_image_path = "/home/gxr/mongodb-run/ebpf_monitor/outputGraph"
output_image_path = os.path.join(output_image_path, 'lock_usage_by_type.png')
plt.savefig(output_image_path, format='png')
plt.show()
