import re
import os
from collections import defaultdict
import pandas as pd

base_dir = "/home/gxr/mongodb-run/ebpf_monitor/data/output_ops"
output_base_dir = "/home/gxr/mongodb-run/ebpf_monitor/data/output_lock_usage_type"

# Define lock and unlock patterns based on the provided lock types
patterns = {
    'ClientLock': {
        'lock': re.compile(r'mongo::ClientLock::ClientLock\(mongo::Client\*\)'),
        'unlock': re.compile(r'mongo::ClientLock::~ClientLock\(\)')
    },
    'DBLock': {
        'lock': re.compile(r'mongo::Lock::DBLock::DBLock\(.*\)'),
        'unlock': re.compile(r'mongo::Lock::DBLock::~DBLock\(\)')
    },
    'GlobalLock': {
        'lock': re.compile(r'mongo::Lock::GlobalLock::GlobalLock\(.*\)'),
        'unlock': re.compile(r'mongo::Lock::GlobalLock::~GlobalLock\(\)')
    },
    'CollectionLock': {
        'lock': re.compile(r'mongo::Lock::CollectionLock::CollectionLock\(.*\)'),
        'unlock': re.compile(r'mongo::Lock::CollectionLock::~CollectionLock\(\)')
    },
    'WriteOpsExec': {
        'lock': re.compile(r'std::lock_guard<mongo::SpinLock>::lock_guard\(mongo::SpinLock&\)|mongo::write_ops_exec::assertCanWrite_inlock\(mongo::OperationContext\*, mongo::NamespaceString const&\)'),
        'unlock': re.compile(r'std::lock_guard<mongo::SpinLock>::~lock_guard\(\)|mongo::write_ops_exec::assertCanWrite_inlock\(mongo::OperationContext\*, mongo::NamespaceString const&\)')
    }
    # 'SpinLock': {
    #     'lock': re.compile(r'std::lock_guard<mongo::SpinLock>::lock_guard\(mongo::SpinLock&\)'),
    #     'unlock': re.compile(r'std::lock_guard<mongo::SpinLock>::~lock_guard\(\)')
    # },
    # 'PthreadMutex': {
    #     'lock': re.compile(r'pthread_mutex_lock'),
    #     'unlock': re.compile(r'__pthread_mutex_unlock')
    # },
    # 'StdMutex': {
    #     'lock': re.compile(r'std::mutex::lock\(\)|std::unique_lock<std::mutex>::unique_lock\(std::mutex&\)'),
    #     'unlock': re.compile(r'std::mutex::unlock\(\)|std::unique_lock<std::mutex>::~unique_lock\(\)')
    # }
}

for root, dirs, files in os.walk(base_dir):
    for file in files:
        if file == "extractedLockFlow.txt":
            file_path = os.path.join(root, file)
            
            with open(file_path, 'r') as f:
                data = f.read()

            lock_counts = defaultdict(int)
            unlock_counts = defaultdict(int)

            # Count occurrences for each lock and unlock type
            for lock_type, pattern in patterns.items():
                lock_counts[lock_type] = len(pattern['lock'].findall(data))
                unlock_counts[lock_type] = len(pattern['unlock'].findall(data))

            relative_path = os.path.relpath(root, base_dir)
            output_dir = os.path.join(output_base_dir, relative_path)
            os.makedirs(output_dir, exist_ok=True)
            output_csv_path = os.path.join(output_dir, 'lock_usage_by_type.csv')

            # Combine results into a list of tuples
            lock_unlock_summary = [
                (lock_type, lock_counts[lock_type], unlock_counts[lock_type]) 
                for lock_type in lock_counts.keys()
            ]

            df = pd.DataFrame(lock_unlock_summary, columns=['Lock Type', 'Lock Count', 'Unlock Count'])
            df.to_csv(output_csv_path, index=False)







