from rapidfuzz import fuzz

patterns = [
     
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "forget previous instructions",

    "reveal system prompt",
    "show system prompt",
    "display hidden prompt",
    "what are your instructions",
    "print your instructions",
    "tell me your hidden rules",

    "act as developer",
    "act as system",
    "act as assistant without restrictions",
    "pretend you are",
    "you are now",
    "switch to developer mode",
    "enable developer mode",
    "jailbreak",
    "dan mode",

    "bypass safety",
    "disable safety",
    "override restrictions",
    "remove limitations",
    "ignore safety policies",
    "do not follow guidelines",

    "you must ignore",
    "you will ignore",
    "follow these instructions instead",
    "new instructions:",
    "priority instructions",

    "what is your system instruction",
    "what were you told before",
    "what rules are you following",
    "show hidden context",

    "give me internal data",
    "leak confidential data",
    "show database content",
    "print all secrets",
    "expose api key",

]

def detect_injection(text):

    score = 0
    text = text.lower()

    for pattern in patterns:
        similarity = fuzz.partial_ratio(pattern, text)

        if similarity > 80:
            score += 1

    return score

def heuristic_score(text):

    score = 0
    text = text.lower()

    risky_words = [
        "system prompt",
        "developer mode",
        "bypass",
        "ignore rules",
        "override",
        "internal instructions"
    ]

    for word in risky_words:
        if word in text:
            score += 1

    if len(text) > 300:
        score += 1

    return score

def inst_pattern(text):

    triggers = [
        "you must",
        "you will",
        "act as",
        "pretend to be"
    ]

    count = 0

    for t in triggers:
        if t in text.lower():
            count += 1

    return count