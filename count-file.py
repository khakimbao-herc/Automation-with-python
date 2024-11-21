import os

def count_files_and_folders(directory):
    total_files = 0
    total_folders = 0

    for root, dirs, files in os.walk(directory):
        total_folders += len(dirs)
        total_files += len(files)

    return total_files, total_folders

directory = '/your/directory/here'
files_count, folders_count = count_files_and_folders(directory)

print(f"Total files: {files_count}")
print(f"Total folders: {folders_count}")