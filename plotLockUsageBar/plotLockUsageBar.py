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


lock_data.plot(kind='bar', stacked=True, ax=ax, position=0, width=0.35, color=['#C9DABF', '#9CA986', '#808D7C', '#5F6F65', '#1A3636'])
unlock_data.plot(kind='bar', stacked=True, ax=ax, position=1, width=0.35, hatch='.',  color=['#C9DABF', '#9CA986', '#808D7C', '#5F6F65', '#1A3636'])

ax.set_title('Lock and Unlock Counts by Lock Type and ops', fontsize=20)
ax.set_xlabel('Ops', fontsize=16)
ax.set_ylabel('Lock Count', fontsize=16)


ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha='right', fontsize=12)


ax.legend(title='Lock Type', loc='upper right', bbox_to_anchor=(1, 1), fontsize=12, title_fontsize=14)


ax.spines['top'].set_linewidth(2)
ax.spines['right'].set_linewidth(2)
ax.spines['bottom'].set_linewidth(2)
ax.spines['left'].set_linewidth(2)


xlim = ax.get_xlim()
ax.set_xlim(xlim[0], xlim[1] + 0.5)  

# Adjust y-axis limits to add padding on top
ylim = ax.get_ylim()
ax.set_ylim(ylim[0], ylim[1] * 1.1)  # Add 10% space above the tallest bar

plt.tight_layout(rect=[0, 0, 0.95, 1])  # Adjust rect to reduce whitespace on the right

output_image_path = "/home/gxr/mongodb-run/ebpf_monitor/outputGraph"
output_image_path = os.path.join(output_image_path, 'lock_usage_by_type.png')
plt.savefig(output_image_path, format='png')
plt.show()
