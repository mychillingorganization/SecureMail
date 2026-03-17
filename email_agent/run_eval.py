import csv
import sys
import time

from email_agent.llm_analyzer import LLMContentAnalyzer

sys.stdout.reconfigure(encoding='utf-8')

# Configuration
CSV_PATH = "email_agent/data/Phishing_validation_emails.csv"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:3b"

def load_test_data(file_path, num_safe=25, num_phishing=25):
    """Read data from CSV and extract the required number of samples"""
    safe_emails = []
    phishing_emails = []

    with open(file_path, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get("Email Text", "")
            label = row.get("Email Type", "")
            
            if label == "Safe Email" and len(safe_emails) < num_safe:
                safe_emails.append(text)
            elif label == "Phishing Email" and len(phishing_emails) < num_phishing:
                phishing_emails.append(text)
                
            if len(safe_emails) >= num_safe and len(phishing_emails) >= num_phishing:
                break
                
    return safe_emails, phishing_emails

def run_evaluation(f):
    print(f"Initializing LLM Analyzer connecting to {OLLAMA_URL} using model {MODEL}...", file=f)
    try:
        analyzer = LLMContentAnalyzer(ollama_url=OLLAMA_URL, model=MODEL)
    except Exception as e:
        print(f"Initialization Error: {e}", file=f)
        return

    print(f"Reading data from {CSV_PATH}...", file=f)
    safe_emails, phishing_emails = load_test_data(CSV_PATH)
    
    test_cases = []
    for text in safe_emails:
        test_cases.append({"text": text, "expected": "safe"})
    for text in phishing_emails:
        test_cases.append({"text": text, "expected": "phishing"})
        
    print(f"\nStarting evaluation on {len(test_cases)} emails...\n" + "="*50, file=f)
    
    correct_count = 0
    
    for i, case in enumerate(test_cases, 1):
        print(f"\n[Test {i}/{len(test_cases)}] Expected Label: {case['expected'].upper()}", file=f)
        print(f"Content: {case['text']}", file=f)
        
        start_time = time.time()
        # For this dataset, there is only a body and no subject, combining them
        result = analyzer.analyze(subject="No Subject", body=case["text"])
        elapsed_time = time.time() - start_time
        
        actual_label = result.get("classification", "unknown")
        confidence = result.get("confidence", 0.0)
        reasoning = result.get("reasoning", "")
        
        is_correct = actual_label == case["expected"]
        if is_correct:
            correct_count += 1
            print(f"CORRECT! (Processing Time: {elapsed_time:.2f}s)", file=f)
        else:
            print(f"INCORRECT! (Processing Time: {elapsed_time:.2f}s)", file=f)
            
        print(f"  - Model Output: {actual_label.upper()} (Confidence: {confidence})", file=f)
        print(f"  - Reasoning: {reasoning}", file=f)
        print("-" * 50, file=f)
        
    print("\n" + "="*50, file=f)
    print(f"SUMMARY: Correct {correct_count}/{len(test_cases)} ({(correct_count/len(test_cases))*100:.2f}%)", file=f)
    if correct_count >= len(test_cases):
        print("🎉 SUCCESS: All test emails classified correctly!", file=f)
    elif (correct_count / len(test_cases)) >= 0.8:
        print("✅ GOOD: Accuracy >= 80%. Consider tuning the prompt for edge cases.", file=f)
    else:
        print("⚠️ FAILED: Accuracy below 80%. Try fine-tuning the prompt or checking the model.", file=f)

if __name__ == "__main__":
    with open("test_results.txt", "w", encoding="utf-8") as f:
        run_evaluation(f)
