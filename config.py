import os
from typing import Optional

class Config:
    """Configuration management for AutoPatchAI"""
    
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