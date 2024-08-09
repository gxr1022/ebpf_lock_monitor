def replace_tabs_with_spaces(file_path, num_spaces=4):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    with open(file_path, 'w') as file:
        for line in lines:
            # Replace tabs with spaces
            new_line = line.replace('\t', ' ' * num_spaces)
            file.write(new_line)

# 使用你的Python文件路径
replace_tabs_with_spaces('/home/gxr/mongodb-run/ebpf_monitor/src/lock_flow_analysis.py')
