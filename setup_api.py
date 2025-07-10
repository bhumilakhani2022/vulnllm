#!/usr/bin/env python3
"""
AutoPatchAI API Setup Script
This script helps you configure your Gemini API key for AutoPatchAI.
"""

import os
import sys
import requests
from config import Config


def setup_api_keys():
    """Interactive setup for Gemini API keys"""
    print("🔒 AutoPatchAI API Setup")
    print("=" * 40)

    # --- Gemini API Key Setup ---
    print("\n--- Gemini API Key ---")
    if Config.validate_gemini_key():
        print("✅ Gemini API key is already configured.")
        print(f"Current key: {Config.GEMINI_API_KEY[:10]}...")
        change_gemini = input(
            "Do you want to change it? (y/N): ").lower().strip()
        if change_gemini == 'y':
            configure_gemini_key()
    else:
        configure_gemini_key()

    print("\n✨ Setup complete!")


def configure_gemini_key():
    """Handles the configuration process for the Gemini API key."""
    print("\nTo use AI-powered features, you need a Gemini API key.")
    print("Get your API key from: https://aistudio.google.com/app/apikey")

    api_key = input("Enter your Gemini API key: ").strip()

    if not api_key:
        print("❌ Invalid or no Gemini API key provided. Skipping.")
        return

    print("\n🔍 Testing Gemini API key...")
    try:
        headers = {'Authorization': f'Bearer {api_key}'}
        test_payload = {"model": "gemini-pro",
                        "messages": [{"role": "user", "content": "Hello"}]}
        response = requests.post(
            Config.GEMINI_API_URL, headers=headers, json=test_payload, timeout=10)

        if response.status_code == 200:
            print("✅ Gemini API key is valid!")
            Config.set_gemini_key(api_key)
            update_env_file('GEMINI_API_KEY', api_key)
            print("✅ Gemini API key saved successfully!")
        else:
            print(
                f"❌ Gemini API key test failed. Status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error testing Gemini API key: {e}")


def update_env_file(key: str, value: str):
    """Update or add a key-value pair in the .env file."""
    env_file = '.env'
    lines = []
    key_found = False

    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            lines = f.readlines()

    with open(env_file, 'w') as f:
        for line in lines:
            if line.strip().startswith(key + '='):
                f.write(f'{key}={value}\n')
                key_found = True
            else:
                f.write(line)
        if not key_found:
            f.write(f'{key}={value}\n')


def main():
    """Main setup function"""
    try:
        setup_api_keys()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

