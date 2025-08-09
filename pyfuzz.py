from argparse import ArgumentParser
from requests import get
from os.path import isfile
from threading import Thread
from datetime import datetime
from time import time

parser = ArgumentParser(description="PyFuzz: a web service fuzzing tool")

parser.add_argument("-u", "--url", required=True, help="Target web service URL")
parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file for fuzzing")
parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads to use (optional, default=1)")
parser.add_argument("--include-sc", type=str, default="200",  help="Comma-separated list of status codes to include (e.g. 200,301,404)")
parser.add_argument("--exclude-len", type=str, help="Comma-separated list of response lengths to exclude from output (e.g. 123,456)")
parser.add_argument("--cookies", type=str, help="Cookies in JSON format to include in requests")

args = parser.parse_args()

FOUND_LIST = []

def split_list(lst, n):
    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]

def timestamp():
    return datetime.now().strftime("[%Y-%m-%d %H:%M:%S")

def fuzz_url(url, word):
    fuzzed_url = url.replace("FUZZ", word)
    try:
        response = get(fuzzed_url, cookies=COOKIES) if COOKIES else get(fuzzed_url)
        length = len(response.text)
        if length in EXCLUDE_LEN:
            return
        if response.status_code in INCLUDE_SC:
            print(f"[{timestamp()}] [+] Found: {fuzzed_url} (Status: {response.status_code}, Length: {length})")
            FOUND_LIST.append({"url": fuzzed_url, "status_code": response.status_code, "length": length})
        else:
            print(f"[{timestamp()}] [-] Not found: {fuzzed_url} (Status: {response.status_code}, Length: {length})")
    except Exception as e:
        print(f"[{timestamp()}] Error accessing {fuzzed_url}: {e}")

def worker(url, chunk):
    for w in chunk:
        print(f"{timestamp()}] Fuzzing: {w}")
        fuzz_url(url, w)

URL, WORDLIST, THREADS = args.url, args.wordlist, args.threads

# Parse cookies argument
COOKIES = None
if args.cookies:
    import json
    try:
        COOKIES = json.loads(args.cookies)
        if not isinstance(COOKIES, dict):
            print("[x] Error: Cookies must be a JSON object.")
            exit(1)
    except Exception as e:
        print(f"[x] Error parsing cookies JSON: {e}")
        exit(1)

# Parse exclude-len argument
EXCLUDE_LEN = []
if args.exclude_len:
    EXCLUDE_LEN = [int(x.strip()) for x in args.exclude_len.split(',') if x.strip().isdigit()]

# Parse include-sc argument
INCLUDE_SC = []
if args.include_sc:
    INCLUDE_SC = [int(code.strip()) for code in args.include_sc.split(',') if code.strip().isdigit()]

# Check if wordlist file exists
if not isfile(WORDLIST):
    print(f"[x] Error: The wordlist file '{WORDLIST}' does not exist.")
    exit(1)

# Check if URL contains 'FUZZ'

if "FUZZ" not in URL:
    print("[x] Error: The URL must contain the string 'FUZZ' at least once.")
    exit(1)

# Read wordlist and split for threads
with open(WORDLIST, "r", encoding="utf-8", errors="ignore") as f:
    words = [line.strip() for line in f if line.strip()]

if not words:
    print("[x] Error: The wordlist file is empty.")
    exit(1)

wordlist_chunks = split_list(words, THREADS)

# Multithreading for fuzzing

start_time = time()
print(f"{timestamp()} [+] Starting fuzzing with {THREADS} threads...")

threads_list = []
for chunk in wordlist_chunks:
    t = Thread(target=worker, args=(URL, chunk))
    threads_list.append(t)
    t.start()

for t in threads_list:
    t.join()

end_time = time()
elapsed = end_time - start_time

# Print results after all threads complete
print(f"\n{timestamp()} [+] Fuzzing complete. Results:")
for result in FOUND_LIST:
    print(f"[+] Found URL: {result['url']}, Status Code: {result['status_code']}, Length: {result['length']}")
print(f"[{timestamp()}] Elapsed duration: {elapsed:.2f} seconds")