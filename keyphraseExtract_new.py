"""
Install the Google AI Python SDK

$ pip install google-generativeai
"""

from google import genai
from google.genai import types
import json
from config import GOOGLE_CLOUD_CONFIG, MODEL_CONFIG, TEST_EXAMPLES

def create_client():
    """Create and return a configured genai client."""
    return genai.Client(
        vertexai=True,
        project=GOOGLE_CLOUD_CONFIG["project"],
        location=GOOGLE_CLOUD_CONFIG["location"],
    )


def create_generate_config():
    """Create generation configuration from config file."""
    safety_settings = [
        types.SafetySetting(
            category=setting["category"],
            threshold=setting["threshold"]
        ) for setting in MODEL_CONFIG["safety_settings"]
    ]
    
    return types.GenerateContentConfig(
        temperature=MODEL_CONFIG["temperature"],
        top_p=MODEL_CONFIG["top_p"],
        max_output_tokens=MODEL_CONFIG["max_output_tokens"],
        safety_settings=safety_settings,
        system_instruction=[types.Part.from_text(text=MODEL_CONFIG["system_instruction"])],
    )

def test_with_examples():
    """Test model with predefined examples from config."""
    client = create_client()
    config = create_generate_config()
    
    print("Testing fine-tuned model with example CVE descriptions...\n")
    
    for i, example in enumerate(TEST_EXAMPLES, 1):
        print(f"=== Test {i} ===")
        print(f"Input: {example['description'][:100]}...")
        print(f"Expected: {example['expected_response']}")
        print("Model Output: ", end="")
        
        contents = [
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=example['description'])]
            )
        ]
        
        try:
            response_text = ""
            for chunk in client.models.generate_content_stream(
                model=MODEL_CONFIG["model_endpoint"],
                contents=contents,
                config=config,
            ):
                response_text += chunk.text
                print(chunk.text, end="")
            
            print("\n")
            
            # Validate JSON format
            try:
                parsed = json.loads(response_text)
                print("✅ Valid JSON format")
            except json.JSONDecodeError:
                print("❌ Invalid JSON format")
            
            print("-" * 80)
            
        except Exception as e:
            print(f"❌ Error: {e}")
            print("-" * 80)

def test_interactive():
    """Interactive testing mode - enter your own CVE descriptions."""
    client = create_client()
    config = create_generate_config()
    
    print("Interactive testing mode. Enter CVE descriptions (or 'quit' to exit):")
    
    while True:
        print("\nEnter CVE description:")
        user_input = input("> ")
        
        if user_input.lower() in ['quit', 'exit', 'q']:
            break
        
        if not user_input.strip():
            continue
        
        print("Model Output: ", end="")
        
        contents = [
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=user_input)]
            )
        ]
        
        try:
            response_text = ""
            for chunk in client.models.generate_content_stream(
                model=MODEL_CONFIG["model_endpoint"],
                contents=contents,
                config=config,
            ):
                response_text += chunk.text
                print(chunk.text, end="")
            
            print("\n")
            
            # Validate JSON format
            try:
                parsed = json.loads(response_text)
                print("✅ Valid JSON format")
                
                # Show parsed structure
                print("Parsed key phrases:")
                for key, value in parsed.items():
                    print(f"  {key}: {value}")
                    
            except json.JSONDecodeError:
                print("❌ Invalid JSON format")
                
        except Exception as e:
            print(f"❌ Error: {e}")

def test_original_format():
    """Test with the original conversation format from your code."""
    client = create_client()
    config = create_generate_config()
    
    print("Testing with original conversation format...\n")
    
    # Your original examples
    msg1_text1 = types.Part.from_text(text="""SQL injection in the admin web console of Ivanti CSA before version 5.0.2 allows a remote authenticated attacker with admin privileges to run arbitrary SQL statements.""")
    msg2_text1 = types.Part.from_text(text="""{\"rootcause\": \"\", \"weakness\": \"SQL injection\", \"impact\": \"execute arbitrary SQL statements\", \"vector\": \"\", \"attacker\": \"remote authenticated attacker with admin privileges\", \"product\": \"Ivanti CSA\", \"version\": \"before version 5.0.2\", \"component\": \"admin web console\"}""")
    msg3_text1 = types.Part.from_text(text="""libuv is a multi-platform support library with a focus on asynchronous I/O. The uv_getaddrinfo function in src/unix/getaddrinfo.c (and its windows counterpart src/win/getaddrinfo.c), truncates hostnames to 256 characters before calling getaddrinfo. This behavior can be exploited to create addresses like 0x00007f000001, which are considered valid by getaddrinfo and could allow an attacker to craft payloads that resolve to unintended IP addresses, bypassing developer checks. The vulnerability arises due to how the hostname_ascii variable (with a length of 256 bytes) is handled in uv_getaddrinfo and subsequently in uv__idna_toascii. When the hostname exceeds 256 characters, it gets truncated without a terminating null byte. As a result attackers may be able to access internal APIs or for websites (similar to MySpace) that allows users to have username.example.com pages. Internal services that crawl or cache these user pages can be exposed to SSRF attacks if a malicious user chooses a long vulnerable username. This issue has been addressed in release version 1.48.0. Users are advised to upgrade. There are no known workarounds for this vulnerability.""")
    msg4_text1 = types.Part.from_text(text="""{\"rootcause\": \"truncating hostnames to 256 characters\", \"weakness\": \"\", \"impact\": \"create addresses like 0x00007f000001, bypassing developer checks\", \"vector\": \"\", \"attacker\": \"attacker\", \"product\": \"Ivanti CSA\", \"version\": \"\", \"component\": \"uv_getaddrinfo function in src/unix/getaddrinfo.c (and its windows counterpart src/win/getaddrinfo.c)\"}""")
    msg5_text1 = types.Part.from_text(text="""A vulnerability in the REST API of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to perform a command injection attack and elevate privileges to root. This vulnerability is due to insufficient input validation for specific API endpoints. An attacker in a man-in-the-middle position could exploit this vulnerability by intercepting and modifying specific internode communications from one ISE persona to another ISE persona. A successful exploit could allow the attacker to run arbitrary commands with root privileges on the underlying operating system. To exploit this vulnerability, the attacker would need to decrypt HTTPS traffic between two ISE personas that are located on separate nodes.""")

    contents = [
        types.Content(role="user", parts=[msg1_text1]),
        types.Content(role="model", parts=[msg2_text1]),
        types.Content(role="user", parts=[msg3_text1]),
        types.Content(role="model", parts=[msg4_text1]),
        types.Content(role="user", parts=[msg5_text1]),
    ]

    print("Processing Cisco ISE vulnerability...")
    print("Model Output: ", end="")
    
    for chunk in client.models.generate_content_stream(
        model=MODEL_CONFIG["model_endpoint"],
        contents=contents,
        config=config,
    ):
        print(chunk.text, end="")
    
    print("\n")

def main():
    """Main function with test options."""
    print("Fine-tuned Model Testing Suite")
    print("=" * 40)
    print("1. Test with predefined examples")
    print("2. Interactive testing")
    print("3. Test with original conversation format")
    print("4. Run all tests")
    
    choice = input("\nSelect option (1-4): ").strip()
    
    if choice == "1":
        test_with_examples()
    elif choice == "2":
        test_interactive()
    elif choice == "3":
        test_original_format()
    elif choice == "4":
        test_with_examples()
        print("\n" + "="*40)
        test_original_format()
    else:
        print("Invalid choice. Running predefined examples...")
        test_with_examples()

if __name__ == "__main__":
    main()