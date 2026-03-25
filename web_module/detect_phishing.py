"""
Phishing URL Detection Console Application
Refactored to use shared Web Agent modules.
"""

import asyncio
import sys
import pandas as pd
from colorama import init, Fore, Style

try:
    from web_module.model import MODEL_PATH, PhishingModel
    from web_module.lists import is_blacklisted, is_whitelisted, load_lists
    from web_module.feature_extractor import extract_html_features, extract_url_features, fetch_url_context
except ImportError:  # Fallback for running from inside the web_module directory.
    from model import PhishingModel, MODEL_PATH
    from lists import load_lists, is_blacklisted, is_whitelisted
    from feature_extractor import extract_url_features, extract_html_features, fetch_url_context

init(autoreset=True)

async def initialize():
    print(f"{Fore.CYAN}Loading threat lists and model...{Style.RESET_ALL}")
    await load_lists()
    model = PhishingModel(MODEL_PATH)
    return model

async def predict_url(model: PhishingModel, url: str, use_html_mode: bool = False):
    print(f"\n{Fore.CYAN}Analyzing URL: {url}{Style.RESET_ALL}")
    print("-" * 80)

    # Fast paths
    if is_blacklisted(url):
        print(f"\n{Fore.YELLOW}PREDICTION RESULTS:{Style.RESET_ALL}")
        print("=" * 80)
        print(f"{Fore.RED}⚠️  WARNING: This URL is BLACKLISTED and treated as PHISHING!{Style.RESET_ALL}")
        print(f"\nRisk Level: {Fore.RED}HIGH RISK{Style.RESET_ALL}")
        print("=" * 80)
        return {'url': url, 'prediction': 'PHISHING', 'phishing_probability': '99.00%', 'source': 'BLACKLIST'}

    if is_whitelisted(url):
        print(f"\n{Fore.YELLOW}PREDICTION RESULTS:{Style.RESET_ALL}")
        print("=" * 80)
        print(f"{Fore.GREEN}✓ This URL appears to be LEGITIMATE{Style.RESET_ALL}")
        print(f"\nRisk Level: {Fore.GREEN}LOW RISK{Style.RESET_ALL}")
        print("=" * 80)
        return {'url': url, 'prediction': 'LEGITIMATE', 'phishing_probability': '1.00%', 'source': 'WHITELIST'}

    print(f"{Fore.CYAN}Extracting features...{Style.RESET_ALL}")
    
    analysis_url = url
    html_content = None
    if use_html_mode:
        try:
            fetched_url, html_content, redirection_chain = await fetch_url_context(url)
            analysis_url = fetched_url or url
            
            # Check intermediate redirects
            for chain_url in redirection_chain:
                if chain_url != url and is_blacklisted(chain_url):
                    print(f"\n{Fore.YELLOW}PREDICTION RESULTS:{Style.RESET_ALL}")
                    print(f"{Fore.RED}⚠️  WARNING: A redirect URL is BLACKLISTED!{Style.RESET_ALL}")
                    return {'url': url, 'prediction': 'PHISHING', 'phishing_probability': '99.00%', 'source': 'BLACKLIST (Redirect)'}
            
            print(f"{Fore.GREEN}✓ HTML fetched successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠ HTML fetch failed: {e}. Using default HTML feature values.{Style.RESET_ALL}")

    url_features = extract_url_features(analysis_url)
    if html_content:
        html_features = extract_html_features(html_content)
    else:
        try:
            from web_module.feature_extractor import HTML_DEFAULT_FEATURES
        except ImportError:
            from feature_extractor import HTML_DEFAULT_FEATURES
        html_features = dict(HTML_DEFAULT_FEATURES)

    all_features = {**url_features, **html_features}
    
    try:
        result = model.predict(all_features)
        
        phishing_prob = result['confidence'] * 100 if result['label'] == 'phishing' else (1 - result['confidence']) * 100
        legit_prob = 100 - phishing_prob
        
        print(f"\n{Fore.YELLOW}PREDICTION RESULTS:{Style.RESET_ALL}")
        print("=" * 80)
        if result['label'] == 'phishing':
            print(f"{Fore.RED}⚠️  WARNING: This URL appears to be PHISHING!{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✓ This URL appears to be LEGITIMATE{Style.RESET_ALL}")
            
        print(f"\nConfidence Scores:")
        print(f"  Legitimate: {Fore.GREEN}{legit_prob:.2f}%{Style.RESET_ALL}")
        print(f"  Phishing:   {Fore.RED}{phishing_prob:.2f}%{Style.RESET_ALL}")
        
        print(f"\nRisk Level: ", end="")
        if result['risk_score'] >= 0.8:
            print(f"{Fore.RED}HIGH RISK{Style.RESET_ALL}")
        elif result['risk_score'] >= 0.5:
            print(f"{Fore.YELLOW}MEDIUM RISK{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}LOW RISK{Style.RESET_ALL}")
        print("=" * 80)
        
        return {
            'url': url,
            'prediction': result['label'].upper(),
            'phishing_probability': f"{phishing_prob:.2f}%",
            'source': 'MODEL'
        }
    except Exception as e:
        print(f"{Fore.RED}✗ Error making prediction: {e}{Style.RESET_ALL}")
        return {'url': url, 'prediction': 'ERROR', 'phishing_probability': '0%', 'source': 'ERROR'}

def display_header():
    print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'PHISHING URL DETECTION SYSTEM':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'Powered by XGBoost Machine Learning':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}\n")

async def run_interactive_mode(model, use_html_mode=False):
    display_header()
    while True:
        try:
            print(f"\n{Fore.YELLOW}Enter a URL to check (or 'quit' to exit):{Style.RESET_ALL}")
            url = input("> ").strip()
            if url.lower() in ['quit', 'exit', 'q']:
                break
            if not url:
                continue
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            await predict_url(model, url, use_html_mode)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"{Fore.RED}✗ Unexpected error: {e}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Thank you for using Phishing Detection System!{Style.RESET_ALL}")

async def run_batch_mode(model, urls, use_html_mode=False):
    display_header()
    print(f"{Fore.YELLOW}Processing {len(urls)} URLs...{Style.RESET_ALL}\n")
    results = []
    for idx, url in enumerate(urls, 1):
        print(f"\n[{idx}/{len(urls)}]", end=" ")
        result = await predict_url(model, url, use_html_mode)
        if result:
            results.append(result)
    
    results_df = pd.DataFrame(results)
    output_file = "detection_results.csv"
    results_df.to_csv(output_file, index=False)
    print(f"\n{Fore.GREEN}✓ Results saved to {output_file}{Style.RESET_ALL}")

async def main_async():
    model = await initialize()
    
    use_html_mode = '--with-html' in sys.argv[1:]
    args = [arg for arg in sys.argv[1:] if arg != '--with-html']
    
    mode_text = "ON" if use_html_mode else "OFF"
    print(f"{Fore.CYAN}ℹ Runtime HTML fetch+parse mode: {mode_text}{Style.RESET_ALL}")
    
    if len(args) > 0:
        await run_batch_mode(model, args, use_html_mode)
    else:
        await run_interactive_mode(model, use_html_mode)

def main():
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
