import re
import os
from datetime import datetime

input_path = '/home/gxr/mongodb-run/ebpf_monitor/data/input_ops'
output_path = '/home/gxr/mongodb-run/ebpf_monitor/data/output_ops'
# Function to clean each line of the stack trace while preserving leading spaces
def clean_stack_line(line):
    leading_whitespace = re.match(r"\s*", line).group(0)
    # Remove "b'", "'", "[mongod]", "[libc.so.6]", and anything in parentheses (e.g., addresses)
    cleaned_line = re.sub(r"b'|'|\[.*?\]|\s\([0-9a-fA-Fx]+\)", '', line)
    return leading_whitespace + cleaned_line.strip()

# Function to clean the file and retain only 'lock' or 'Lock' related stack entries
def clean_lock_file(input_file_path, output_file_path):
    
    with open(input_file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Initialize variables for processing
    cleaned_content = []
    inside_mutex_section = False
    current_section = []

    # Process the content line by line
    for line in content.splitlines():
        if 'At time' in line:
            # Save the previous mutex section if there is one
            if current_section:
                cleaned_content.extend(current_section)
                current_section = []
            # Start a new mutex section
            cleaned_content.append(line)
            inside_mutex_section = True
        elif inside_mutex_section:
            if line.strip() == "":
                # End of the current mutex section
                inside_mutex_section = False
                if current_section:
                    cleaned_content.extend(current_section)
                    cleaned_content.append("")  # Add a newline to separate sections
                    current_section = []
            elif "lock" in line or "Lock(" in line:
                # Clean the stack line before adding it
                cleaned_line = clean_stack_line(line)
                current_section.append(cleaned_line)

    # Ensure the last section is added to the cleaned content
    if current_section:
        cleaned_content.extend(current_section)

    # Join the cleaned content into a single string
    cleaned_content_str = "\n".join(cleaned_content)

    # Save the cleaned content to a new file
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        output_file.write(cleaned_content_str)


# current_datetime = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
# new_input_path = os.path.join(input_path, current_datetime)
# new_output_path = os.path.join(output_path, current_datetime)
# os.makedirs(new_input_path, exist_ok=True)
# os.makedirs(new_output_path, exist_ok=True)

folders = [f.name for f in os.scandir(input_path) if f.is_dir()]

for folder in folders:
    # Construct the input file path
    input_file_folder = os.path.join(input_path, folder)
    input_file_path = os.path.join(input_file_folder, '1')

    
    
    # Construct the output file path
    output_file_folder = os.path.join(output_path, folder)
    output_file_path = os.path.join(output_file_folder, 'extractedLockFlow.txt')
    os.makedirs(output_file_folder, exist_ok=True)

    clean_lock_file(input_file_path, output_file_path)



# print(f"Cleaned file has been saved to: {output_file_path}")
