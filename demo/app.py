import gradio as gr
from sovereign_vault import VaultSession

def process_text(text):
    if not text.strip():
        return "", "Please enter some text."
        
    with VaultSession(use_gliner=False, use_ollama=False) as vault:
        abstract = vault.tokenize(text)
        diff_output = vault.diff()
        
    return abstract, diff_output

with gr.Blocks(theme=gr.themes.Soft(primary_hue="blue")) as demo:
    gr.Markdown("# 🛡️ Sovereign Vault - PII Redaction Demo")
    gr.Markdown("Test the `sovereign-vault` reversible tokenization pipeline. This demo runs the **Layer 1 (Deterministic Regex)** engine. The full package also supports GLiNER and Ollama layers.")
    
    with gr.Row():
        with gr.Column():
            input_text = gr.Textbox(
                label="Input Text (Contains PII)", 
                lines=5, 
                placeholder="Enter text containing an SSN (e.g., 123-45-6789), email, phone, or IP address..."
            )
            tokenize_btn = gr.Button("Vault Tokenize", variant="primary")
            
        with gr.Column():
            output_text = gr.Textbox(label="Tokenized Output (Safe for LLM)", lines=5)
            
    with gr.Row():
        diff_view = gr.Textbox(label="Detection Audit (vault.diff())", lines=8, font="monospace")
        
    tokenize_btn.click(
        fn=process_text,
        inputs=[input_text],
        outputs=[output_text, diff_view]
    )
    
    gr.Examples(
        examples=[
            ["John Doe (SSN: 123-45-6789, email: john@example.com) sent funds to Jane Smith."],
            ["The server at 192.168.1.50 was accessed by user with phone 555-019-8372."],
            ["Case #24-123456-CZ: Patient reports symptoms. Contact at jane.doe@hospital.org."]
        ],
        inputs=[input_text]
    )

if __name__ == "__main__":
    demo.launch()
