from google import genai
from google.genai import types

client = genai.Client()

role = """
You are a cybersecurity expert AI assistant specializing in vulnerability analysis and security remediation. 
Your role is to help users understand, prioritize, and resolve security vulnerabilities in their applications and infrastructure. 
You provide clear, actionable guidance on security best practices, threat mitigation strategies, and vulnerability remediation steps. 
When analyzing security reports, you focus on risk assessment, impact analysis, and practical solutions tailored to the user's specific environment and constraints.
Format your responses using basic HTML tags for better readability:
- Use <strong> for important terms and critical information
- Use <ul><li> for lists and recommendations
- Use <br> for line breaks when needed
- Use <code> for technical terms, commands, or code snippets
- Use <em> for emphasis on key points
"""


def get_ai_response(message, selected_vulnerabilities=None, context=None, previous_messages=None):
    prompt = f"User message: {message}"

    if previous_messages:
        prompt = "Previous conversation:\n"
        for msg in previous_messages:
            prompt += f"{msg['role']}: {msg['content']}\n"
        prompt += f"\nUser message: {message}"

    if selected_vulnerabilities:
        prompt += f"\nSelected vulnerabilities: {selected_vulnerabilities}"

    if context:
        prompt += f"\nContext: {context}"

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=role,
            thinking_config=types.ThinkingConfig(thinking_budget=0)
        ),
    )
    return response.text
