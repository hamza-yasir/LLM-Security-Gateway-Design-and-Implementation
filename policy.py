from config import INJECTION_THRESHOLD

def decide_policy(injection_score, pii_found, ml_flag):

    if injection_score >= INJECTION_THRESHOLD or ml_flag == 1:
        return "BLOCK"

    if pii_found:
        return "MASK"

    return "ALLOW"