#!/usr/bin/env python3
"""Automated deploy loop for production.

This script continuously polls the local Git repository for new changes,
merges them to main, force pushes, tags the commit, runs tests, and
deploys to Firebase Hosting. It is intended to be run by an automation
agent or CI job and assumes necessary credentials are already
configured (Firebase CLI auth, SSH keys, etc.).
"""
import os
import subprocess
import time
from datetime import datetime

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
REMOTE = os.environ.get("DEPLOY_REMOTE", "origin")
BRANCH = os.environ.get("DEPLOY_BRANCH", "main")
CHECK_INTERVAL = int(os.environ.get("DEPLOY_INTERVAL", "60"))  # seconds


def run(cmd):
    """Run command and return output."""
    print(f"[deploy_agent] $ {cmd}")
    result = subprocess.run(cmd, shell=True, cwd=REPO_DIR,
                            text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    print(result.stdout)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}")
    return result.stdout


def current_hash():
    return run("git rev-parse HEAD").strip()


def remote_exists(remote_name: str) -> bool:
    try:
        run(f"git remote get-url {remote_name}")
        return True
    except RuntimeError:
        print(f"[deploy_agent] Remote '{remote_name}' not configured; skipping fetch")
        return False


def main_loop():
    last_deployed = current_hash()
    while True:
        try:
            if remote_exists(REMOTE):
                run(f"git fetch {REMOTE}")
                run(f"git merge --ff-only {REMOTE}/{BRANCH} || git merge {REMOTE}/{BRANCH}")
            new_hash = current_hash()
            if new_hash != last_deployed:
                if remote_exists(REMOTE):
                    run(f"git push --force {REMOTE} {BRANCH}")
                tag = f"prod-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{new_hash[:7]}"
                run(f"git tag {tag}")
                if remote_exists(REMOTE):
                    run(f"git push --force {REMOTE} {tag}")
                run("docker buildx build --tag wifite3:prod .")
                run("docker run --rm wifite3:prod python -m unittest discover -v tests")
                run("firebase deploy --only hosting")
                last_deployed = new_hash
        except Exception as exc:
            print(f"[deploy_agent] Error: {exc}")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main_loop()
