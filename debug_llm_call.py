import os
import logging
from src.llm_client import LLMClient

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Force configuration to match docker-compose environment for testing
# We assume this script runs on the host, so we need to point to the exposed port 8000
# If running inside container, we'd use http://mock-llm:8000/v1
# But from the user's perspective (host), we use localhost:8000
os.environ["LLM_PROVIDER"] = "local"
os.environ["LOCAL_LLM_URL"] = "http://localhost:8000/v1"

def test_red_team_call():
    client = LLMClient()
    
    system_prompt = "You are a Red Team simulator."
    # Use exact phrase from AdversarialPersonaEmulator to match mock server logic
    user_prompt = """
    ## CURRENT SITUATION
    ...
    ## YOUR MISSION
    Given the above intelligence, execute your Red Team analysis.
    """
    
    logger.info("🚀 Sending Red Team request...")
    try:
        response = client._call_openai_chat(system_prompt, user_prompt, is_json=True)
        logger.info(f"✅ Response received: {response}")
        
        if "predicted_kill_chain" in response:
            logger.info("🎉 SUCCESS: 'predicted_kill_chain' found!")
        else:
            logger.error("❌ FAILURE: 'predicted_kill_chain' key MISSING. Falls back to default response?")
            
    except Exception as e:
        logger.error(f"💥 Exception during call: {e}")

if __name__ == "__main__":
    test_red_team_call()
