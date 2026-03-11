import os
import time
import subprocess
import datetime
import sys

def main():
    print("=" * 60)
    print("  VIPER AUTO-SYNC SERVICE")
    print("  Monitoring project directory for changes...")
    print("  Interval: Every 30 seconds")
    print("=" * 60)
    print("\n[>] Press Ctrl+C at any time to stop the auto-sync service.\n")

    try:
        while True:
            # Check if there are any uncommitted changes
            status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
            
            # If the output is not empty, it means files have been modified, added, or deleted
            if status.stdout.strip() != "":
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[!] Changes detected at {current_time}. Syncing to GitHub...")
                
                # 1. Stage all changes
                subprocess.run(["git", "add", "."], check=True)
                
                # 2. Commit the changes
                commit_msg = f"Auto-sync update: {current_time}"
                subprocess.run(["git", "commit", "-m", commit_msg], capture_output=True)
                
                # 3. Push to GitHub
                print("    Pushing to remote repository...")
                push_res = subprocess.run(["git", "push"], capture_output=True, text=True)
                
                if push_res.returncode == 0:
                    print("    [+] Successfully pushed updates to GitHub.\n")
                else:
                    print("    [X] Failed to push to GitHub. Check your connection or git credentials.")
                    print(f"        Error details: {push_res.stderr.strip()}\n")
            
            # Wait for 30 seconds before checking again
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n[!] Auto-Sync Service stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
