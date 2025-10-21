# tools/token_count.py
# Calculates the number of tokens in a given text file using a tokenizer.
# This is useful for understanding the context window overhead of the Mijann shield.

import argparse
import tiktoken

def count_tokens(file_path: str, model_name: str = "gpt-4") -> int:
    """
    Reads a file and counts the number of tokens using the specified model's encoding.

    Args:
        file_path: The path to the text file.
        model_name: The name of the model to get the tokenizer for (e.g., "gpt-4").

    Returns:
        The total number of tokens.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'")
        return 0
    except Exception as e:
        print(f"Error reading file: {e}")
        return 0

    try:
        # Get the encoding for the specified model
        encoding = tiktoken.encoding_for_model(model_name)
        tokens = encoding.encode(text)
        return len(tokens)
    except Exception as e:
        print(f"Error during tokenization: {e}")
        return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Count tokens in a text file.")
    parser.add_argument("file_path", type=str, help="Path to the shield file to analyze.")
    parser.add_argument(
        "--model",
        type=str,
        default="gpt-4",
        help="The model to use for tokenization (e.g., 'gpt-4', 'gpt-3.5-turbo')."
    )

    args = parser.parse_args()
    
    token_count = count_tokens(args.file_path, args.model)
    
    if token_count > 0:
        print(f"File:      {args.file_path}")
        print(f"Tokenizer: {args.model}")
        print(f"Token Count: {token_count}")
