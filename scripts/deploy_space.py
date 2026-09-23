"""Deployment script to create and push AegisAgent to a Hugging Face Space (Docker SDK)."""

import argparse
import os
from pathlib import Path
import sys
from huggingface_hub import HfApi, create_repo


def deploy(token: str, space_name: str = "aegisagent", private: bool = False):
    api = HfApi(token=token)
    user_info = api.whoami()
    username = user_info["name"]
    repo_id = f"{username}/{space_name}"

    print(f"[*] Authenticated as Hugging Face user: {username}")
    print(f"[*] Target Space ID: {repo_id}")

    # 1. Create Space repo with Docker SDK
    print(f"[*] Creating or updating Space '{repo_id}' (SDK: docker)...")
    repo_url = create_repo(
        repo_id=repo_id,
        repo_type="space",
        space_sdk="docker",
        private=private,
        exist_ok=True,
        token=token,
    )
    print(f"[+] Space created/verified: {repo_url}")

    # 2. Upload README_SPACE.md as README.md (containing HF YAML metadata)
    root = Path(__file__).resolve().parent.parent
    readme_space = root / "README_SPACE.md"
    if readme_space.exists():
        print("[*] Uploading README_SPACE.md as README.md (with Space YAML frontmatter)...")
        api.upload_file(
            path_or_fileobj=str(readme_space),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="space",
            token=token,
            commit_message="docs: add Space README with Hugging Face Docker metadata",
        )

    # 3. Upload project folder
    print("[*] Uploading project files to Space...")
    ignore_patterns = [
        "__pycache__/**",
        "*.pyc",
        "*.pyo",
        ".git/**",
        ".pytest_cache/**",
        "venv/**",
        ".venv/**",
        "*.sqlite",
        "*.sqlite3",
        "*.db",
        "reports/retrain_*",
        ".DS_Store",
        "Thumbs.db",
    ]

    api.upload_folder(
        folder_path=str(root),
        repo_id=repo_id,
        repo_type="space",
        ignore_patterns=ignore_patterns,
        token=token,
        commit_message="feat: deploy AegisAgent Prompt Injection Firewall to Space",
    )

    # 4. Set DEMO_MODE=1 environment variable on the Space
    try:
        print("[*] Configuring DEMO_MODE=1 environment variable on Space...")
        api.add_space_variable(repo_id=repo_id, key="DEMO_MODE", value="1", token=token)
        print("[+] Set DEMO_MODE=1")
    except Exception as e:
        print(f"[!] Note: Could not set DEMO_MODE variable via API ({e}). It can also be set in Space settings.")

    print("\n" + "=" * 60)
    print(f"🎉 Deployment Complete!")
    print(f"🚀 Space URL: https://huggingface.co/spaces/{repo_id}")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deploy AegisAgent to Hugging Face Space")
    parser.add_argument("--token", default=os.environ.get("HF_TOKEN"), help="Hugging Face User Access Token (Write)")
    parser.add_argument("--name", default="aegisagent", help="Space name (default: aegisagent)")
    parser.add_argument("--private", action="store_true", help="Create private Space")

    args = parser.parse_args()
    if not args.token:
        print("Error: Hugging Face token must be provided via --token or HF_TOKEN env var.", file=sys.stderr)
        print("Generate a write token at https://huggingface.co/settings/tokens", file=sys.stderr)
        sys.exit(1)

    deploy(token=args.token, space_name=args.name, private=args.private)
