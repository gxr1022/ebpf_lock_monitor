import re
from collections import defaultdict
import pandas as pd
import ace_tools as tools


# Read the file content
with open('/mnt/data/extractedLockFlow.txt', 'r') as file:
    data = file.read()

# Regular expressions to capture lock and unlock operations with mutex ids
lock_pattern = re.compile(r'for mutex (\d+)\s+pthread_mutex_lock')
unlock_pattern = re.compile(r'for mutex (\d+)\s+__pthread_mutex_unlock')

# Dictionaries to store counts
lock_counts = defaultdict(int)
unlock_counts = defaultdict(int)

# Finding all lock and unlock operations
for lock_match in lock_pattern.finditer(data):
    mutex_id = lock_match.group(1)
    lock_counts[mutex_id] += 1

for unlock_match in unlock_pattern.finditer(data):
    mutex_id = unlock_match.group(1)
    unlock_counts[mutex_id] += 1

# Convert results to a list of tuples and sort by mutex_id
lock_unlock_summary = sorted(
    [(mutex_id, lock_counts[mutex_id], unlock_counts[mutex_id]) for mutex_id in lock_counts.keys()],
    key=lambda x: x[0]
)



df = pd.DataFrame(lock_unlock_summary, columns=['Mutex ID', 'Lock Count', 'Unlock Count'])

tools.display_dataframe_to_user(name="Lock and Unlock Counts by Mutex ID", dataframe=df)
