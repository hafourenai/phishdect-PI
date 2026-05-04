import os
import shutil
import sys

def clean_pycache(directory):
    """
    Recursively deletes all __pycache__ directories and .pyc/.pyo files.
    """
    count_dirs = 0
    count_files = 0
    
    print(f"🧹 Memulai pembersihan di: {directory}")
    
    for root, dirs, files in os.walk(directory, topdown=False):
        # Hapus folder __pycache__
        for name in dirs:
            if name == "__pycache__":
                path = os.path.join(root, name)
                try:
                    shutil.rmtree(path)
                    print(f"   [Folder] Berhasil menghapus: {path}")
                    count_dirs += 1
                except Exception as e:
                    print(f"   [Error] Gagal menghapus folder {path}: {e}")

        # Hapus file .pyc dan .pyo yang mungkin tersisa di luar __pycache__
        for name in files:
            if name.endswith(".pyc") or name.endswith(".pyo"):
                path = os.path.join(root, name)
                try:
                    os.remove(path)
                    print(f"   [File]   Berhasil menghapus: {path}")
                    count_files += 1
                except Exception as e:
                    print(f"   [Error] Gagal menghapus file {path}: {e}")

    print("-" * 50)
    print(f"✨ Pembersihan selesai!")
    print(f"✅ Total folder dihapus: {count_dirs}")
    print(f"✅ Total file dihapus: {count_files}")

if __name__ == "__main__":
    # Gunakan direktori saat ini sebagai default
    project_root = os.path.dirname(os.path.abspath(__file__))
    clean_pycache(project_root)
