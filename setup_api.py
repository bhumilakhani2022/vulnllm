#!/usr/bin/env python3
"""
AutoPatchAI API Setup Script
This script helps you configure your OpenAI API key for AutoPatchAI.
"""

import os
import sys
from config import Config


def setup_api_key():
    """Interactive setup for AI API keys (Gemini preferred, OpenAI fallback)"""
    print("🔒 AutoPatchAI API Setup")
    print("=" * 40)

    # Check current API key status
    gemini_configured = Config.validate_gemini_key()
    openai_configured = Config.validate_api_key()

    if gemini_configured:
        print("✅ Gemini API key is already configured! (Preferred)")
        print(f"Current key: {Config.GEMINI_API_KEY[:10]}...")

        change = input("\nDo you want to change it? (y/N): ").lower().strip()
        if change != 'y':
            print("Setup complete!")
            return
    elif openai_configured:
        print("✅ OpenAI API key is already configured!")
        print(f"Current key: {Config.OPENAI_API_KEY[:10]}...")

        change = input(
            "\nDo you want to change it or add Gemini API? (y/N): ").lower().strip()
        if change != 'y':
            print("Setup complete!")
            return

    print("\nAutoPatchAI supports two AI providers:")
    print("1. 🌟 Gemini API (Google) - Recommended, often free")
    print("2. 🔥 OpenAI API - Powerful, requires paid credits")
    print()

    choice = input(
        "Which API would you like to configure? (1 for Gemini, 2 for OpenAI): ").strip()

    if choice == '1':
        setup_gemini_api()
    elif choice == '2':
        setup_openai_api()
    else:
        print("❌ Invalid choice. Setup cancelled.")


def setup_gemini_api():
    """Setup Gemini API key"""
    print("\n🌟 Setting up Gemini API")
    print("Get your API key from: https://aistudio.google.com/app/apikey")
    print()

    # Get API key from user
    api_key = input("Enter your Gemini API key: ").strip()

    if not api_key:
        print("❌ No API key provided. Setup cancelled.")
        return

    # Test the API key
    print("\n🔍 Testing Gemini API key...")
    try:
        import requests

        headers = {
            'Content-Type': 'application/json'
        }

        # Simple test payload
        test_payload = {
            'contents': [
                {
                    'parts': [
                        {
                            'text': 'Hello, respond with just "OK"'
                        }
                    ]
                }
            ]
        }

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"

        response = requests.post(
            url,
            headers=headers,
            json=test_payload,
            timeout=10
        )

        if response.status_code == 200:
            print("✅ Gemini API key is valid!")

            # Save the API key
            Config.set_gemini_key(api_key)

            # Create .env file for persistence
            env_content = f'GEMINI_API_KEY={api_key}\n'

            # Preserve existing OpenAI key if present
            if Config.validate_api_key():
                env_content += f'OPENAI_API_KEY={Config.OPENAI_API_KEY}\n'

            with open('.env', 'w') as f:
                f.write(env_content)

            print("✅ Gemini API key saved successfully!")
            print("\nYou can now use AI-powered features in AutoPatchAI with Gemini.")

        else:
            print(
                f"❌ Gemini API key test failed. Status: {response.status_code}")
            print("Please check your API key and try again.")

    except Exception as e:
        print(f"❌ Error testing Gemini API key: {e}")
        print("Please check your internet connection and try again.")


def setup_openai_api():
    """Setup OpenAI API key"""
    print("\n🔥 Setting up OpenAI API")
    print("Get your API key from: https://platform.openai.com/api-keys")
    print()

    # Get API key from user
    api_key = input("Enter your OpenAI API key: ").strip()

    if not api_key:
        print("❌ No API key provided. Setup cancelled.")
        return

    if api_key == 'your-openai-api-key-here' or not api_key.startswith('sk-'):
        print("❌ Please enter a valid OpenAI API key that starts with 'sk-'.")
        return

    # Test the API key
    print("\n🔍 Testing OpenAI API key...")
    try:
        import requests

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        # Make a simple test call
        test_payload = {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 10
        }

        response = requests.post(
            Config.OPENAI_API_URL,
            headers=headers,
            json=test_payload,
            timeout=10
        )

        if response.status_code == 200:
            print("✅ OpenAI API key is valid!")

            # Save the API key
            Config.set_api_key(api_key)

            # Create .env file for persistence
            env_content = f'OPENAI_API_KEY={api_key}\n'

            # Preserve existing Gemini key if present
            if Config.validate_gemini_key():
                env_content += f'GEMINI_API_KEY={Config.GEMINI_API_KEY}\n'

            with open('.env', 'w') as f:
                f.write(env_content)

            print("✅ OpenAI API key saved successfully!")
            print("\nYou can now use AI-powered features in AutoPatchAI with OpenAI.")

        else:
            print(
                f"❌ OpenAI API key test failed. Status: {response.status_code}")
            print("Please check your API key and try again.")

    except Exception as e:
        print(f"❌ Error testing OpenAI API key: {e}")
        print("Please check your internet connection and try again.")


def main():
    """Main setup function"""
    try:
        setup_api_key()
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user.")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
