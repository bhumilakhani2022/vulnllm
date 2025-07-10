#!/usr/bin/env python3
"""Test script to verify Gemini API connectivity"""

import os
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

def test_gemini_api():
    """Test Gemini API connection"""
    api_key = os.getenv('GEMINI_API_KEY')
    
    if not api_key:
        print("❌ No GEMINI_API_KEY found in environment variables")
        return False
    
    print(f"✅ Found API key: {api_key[:10]}...")
    
    # Test API call - using gemini-1.5-flash (currently available model)
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    
    payload = {
        "contents": [{
            "parts": [{
                "text": "Say hello and confirm you are working"
            }]
        }],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 100
        }
    }
    
    try:
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'})
        response.raise_for_status()
        
        result = response.json()
        if 'candidates' in result and len(result['candidates']) > 0:
            ai_response = result['candidates'][0]['content']['parts'][0]['text']
            print(f"✅ API Response: {ai_response}")
            return True
        else:
            print(f"❌ Unexpected response format: {result}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Response content: {e.response.text}")
        return False

if __name__ == "__main__":
    print("Testing Gemini API connectivity...")
    print("=" * 50)
    
    success = test_gemini_api()
    
    if success:
        print("\n🎉 API test successful!")
    else:
        print("\n💥 API test failed. Please check your configuration.")
