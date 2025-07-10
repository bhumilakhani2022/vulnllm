#!/usr/bin/env python3
"""
AutoPatchAI API Setup Script
This script helps you configure your OpenAI API key for AutoPatchAI.
"""

import os
import sys
from config import Config

def setup_api_key():
    """Interactive setup for OpenAI API key"""
    print("🔒 AutoPatchAI API Setup")
    print("=" * 40)
    
    # Check if API key is already set
    if Config.validate_api_key():
        print("✅ OpenAI API key is already configured!")
        print(f"Current key: {Config.OPENAI_API_KEY[:10]}...")
        
        change = input("\nDo you want to change it? (y/N): ").lower().strip()
        if change != 'y':
            print("Setup complete!")
            return
    
    print("\nTo use AI-powered features, you need an OpenAI API key.")
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
    print("\n🔍 Testing API key...")
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
            print("✅ API key is valid!")
            
            # Save the API key
            Config.set_api_key(api_key)
            
            # Create .env file for persistence
            with open('.env', 'w') as f:
                f.write(f'OPENAI_API_KEY={api_key}\n')
            
            print("✅ API key saved successfully!")
            print("\nYou can now use AI-powered features in AutoPatchAI.")
            
        else:
            print(f"❌ API key test failed. Status: {response.status_code}")
            print("Please check your API key and try again.")
            
    except Exception as e:
        print(f"❌ Error testing API key: {e}")
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