import time

from injection import detect_injection
from injection import heuristic_score
from injection import inst_pattern
from presidio_scan import analyze_pii
from policy import decide_policy
from ml_detect import ml_det

while True:

    print("-" * 55)

    text = input("Enter user input(exit to leave): ")
    if text.lower() == "exit":
        break

    start = time.time()

    injection_score = detect_injection(text) + heuristic_score(text) + inst_pattern(text)

    ml_flag = ml_det(text)

    pii_results, masked_text = analyze_pii(text)

    pii_found = len(pii_results) > 0

    decision = decide_policy(injection_score, pii_found, ml_flag)

    end = time.time()

    latency = end - start



    print("\nDetection Score:", detect_injection(text))
    print("Heuristic Score:", heuristic_score(text))
    print("Pattern Score:", inst_pattern(text))
    print("Total Score:", injection_score)
    print("PII Detected:", pii_found)
    print("ML Detection:", "Malicious" if ml_flag else "Safe")
    print("Decision:", decision)

    if decision == "MASK":
        print("Output:", masked_text)

    elif decision == "BLOCK":
        print("Request blocked due to security policy")

    else:
        print("Output:", text)

    print("Latency:", round(latency,4),"seconds\n")