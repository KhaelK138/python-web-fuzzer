import requests
import threading
import os
import time
import argparse
import sys
from urllib.parse import parse_qsl

print_lock = threading.Lock()

processed_count = 0
total_count = 0
stop_event = threading.Event()

# Update and display progress
def print_progress():
    percent = (processed_count / total_count) * 100
    sys.stdout.write(f"\r[+] Progress: {processed_count}/{total_count} ({percent:.2f}%)")
    sys.stdout.flush()

# Send HTTP requests and filter based on status code or size
def send_request(url, word, filters, data=None):
    global processed_count
    
    if stop_event.is_set():
        return
        
    target_url = url.replace('FUZZ', word)
    
    try:
        if data:  # If data is provided, perform a POST request
            post_data = data.replace('FUZZ', word)
            
            # Set proper headers for form submission
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.post(target_url, data=post_data, headers=headers, timeout=3.0, allow_redirects=False)
        else: 
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(target_url, headers=headers, timeout=3.0, allow_redirects=False)

        with print_lock:
            # Check if the response is a redirect
            if response.status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location', 'Unknown redirect target')
                # Display the redirect information
                sys.stdout.write("\r" + " " * 80 + "\r")  # Clear progress bar
                print(f"[+] Found Redirect: {target_url} - Status: {response.status_code} - Redirected to: {redirect_url}")
                if data:
                    print(f"    - POST Data: {post_data}")
                print_progress()  # Redraw progress bar
                return

            # Check status code filter
            if 'fc' in filters and str(response.status_code) in filters['fc']:
                return  # Skip if status code matches the filter

            # Check size filte
            if 'fs' in filters and response.text and len(response.text) in filters['fs']:
                return  
            
            if response.status_code != 404:
                sys.stdout.write("\r" + " " * 80 + "\r")  # Clear progress bar
                print(f"[+] Found: {target_url} - Status: {response.status_code} - Size: {len(response.text)} bytes")
                if data:
                    print(f"    - POST Data: {post_data}")
                print_progress()  # Redraw progress bar

    except requests.exceptions.RequestException as e:
        pass
    finally:
        with print_lock:
            processed_count += 1
            print_progress()

# Function to handle the threaded fuzzing process
def fuzz(url, wordlist, threads, filters, data=None):
    global processed_count, total_count, stop_event
    
    try:
        with open(wordlist, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading wordlist: {e}")
        sys.exit(1)
        
    total_count = len(words)
    processed_count = 0
    stop_event.clear()
    
    # Adjust number of threads if there are fewer words than threads
    if total_count < threads:
        threads = total_count
        print(f"[*] Adjusting to {threads} threads due to wordlist size...")
    
    print(f"[*] Fuzzing {url} with {total_count} words using {threads} threads...")
    print_progress()  # Initial progress display

    def threaded_fuzz(word_batch):
        for word in word_batch:
            if stop_event.is_set():
                break
            send_request(url, word, filters, data)

    # Split the wordlist into equal batches for each thread
    batches = []
    batch_size = total_count // threads
    remainder = total_count % threads
    
    start = 0
    for i in range(threads):
        # Add one extra item to the first 'remainder' batches to distribute evenly
        current_batch_size = batch_size + (1 if i < remainder else 0)
        end = start + current_batch_size
        batches.append(words[start:end])
        start = end

    threads_list = []
    for batch in batches:
        thread = threading.Thread(target=threaded_fuzz, args=(batch,))
        threads_list.append(thread)
        thread.start()

    try:
        for thread in threads_list:
            thread.join()
        print("\n[*] Fuzzing complete!")
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[!] Interrupted. Cleaning up threads...")
        for t in threads_list:
            t.join()
        print("[*] Cleanup complete.")

def main():
    parser = argparse.ArgumentParser(description="Fuzzing script")
    parser.add_argument("-u", "--url", required=True, help="Target URL with FUZZ placeholder")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-fc", "--filter_codes", help="Comma separated list of status codes to exclude (e.g., 200,301)")
    parser.add_argument("-fs", "--filter_size", help="Comma separated list of response sizes to exclude (e.g., 100,200)")
    parser.add_argument("-d", "--data", help="Data to send in a POST request (e.g., 'username=admin&password=FUZZ')")

    args = parser.parse_args()

    filters = {}

    if args.filter_codes:
        filters['fc'] = args.filter_codes.split(',')
    
    if args.filter_size:
        filters['fs'] = list(map(int, args.filter_size.split(',')))

    # If a POST data string is passed, use it directly
    data = args.data if args.data else None

    try:
        fuzz(args.url, args.wordlist, args.threads, filters, data)
    except KeyboardInterrupt:
        print("\n[!] Program terminated by user.")
        sys.exit(0)

if __name__ == '__main__':
    main()