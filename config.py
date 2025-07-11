import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Configuration management for AutoPatchAI"""

    # Gemini API Configuration
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    GEMINI_API_URL = os.getenv(
        'GEMINI_API_URL', 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent')
    GEMINI_MODEL = "gemini-1.5-flash"

    # OpenAI API Configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', 'enter your api key here')
    OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
    OPENAI_MODEL = "gpt-4"  # or "gpt-3.5-turbo" for cost savings

    # Application Settings
    APP_NAME = "AutoPatchAI"
    APP_VERSION = "1.0.0"

    # Analysis Settings
    DEFAULT_TEMPERATURE = 0.3
    DEFAULT_MAX_TOKENS = 2000

    @classmethod
    def validate_gemini_key(cls) -> bool:
        """Validate if Gemini API key is configured"""
        return cls.GEMINI_API_KEY != ''

    @classmethod
    def get_gemini_key(cls) -> Optional[str]:
        """Get the Gemini API key if valid"""
        if cls.validate_gemini_key():
            return cls.GEMINI_API_KEY
        return None

    @classmethod
    def set_gemini_key(cls, api_key: str) -> None:
        """Set the Gemini API key"""
        cls.GEMINI_API_KEY = api_key
        os.environ['GEMINI_API_KEY'] = api_key

    @classmethod
    def validate_api_key(cls) -> bool:
        """Validate if OpenAI API key is properly configured"""
        return cls.OPENAI_API_KEY != 'enter your api key here' and cls.OPENAI_API_KEY != '' and cls.OPENAI_API_KEY.startswith('sk-')

    @classmethod
    def get_api_key(cls) -> Optional[str]:
        """Get the OpenAI API key if valid"""
        if cls.validate_api_key():
            return cls.OPENAI_API_KEY
        return None

    @classmethod
    def set_api_key(cls, api_key: str) -> None:
        """Set the OpenAI API key"""
        cls.OPENAI_API_KEY = api_key
        os.environ['OPENAI_API_KEY'] = api_key
