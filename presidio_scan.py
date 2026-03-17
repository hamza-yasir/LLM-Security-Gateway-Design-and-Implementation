from presidio_analyzer import   
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer import PatternRecognizer, Pattern


# Initialize engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()


# -------------------------------
# Custom Recognizer 1: API Key
# Example: sk-ABC123XYZ456789
# -------------------------------

api_pattern = Pattern(
    name="api_key_pattern",
    regex=r"sk-[A-Za-z0-9]{16,}",
    score=0.85
)

api_recognizer = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[api_pattern]
)

analyzer.registry.add_recognizer(api_recognizer)


# -------------------------------
# Custom Recognizer 2: Employee ID
# Example: EMP-12345
# -------------------------------

emp_pattern = Pattern(
    name="employee_id_pattern",
    regex=r"EMP-[0-9]{4,6}",
    score=0.8
)

emp_recognizer = PatternRecognizer(
    supported_entity="EMPLOYEE_ID",
    patterns=[emp_pattern]
)

analyzer.registry.add_recognizer(emp_recognizer)


# -------------------------------
# Custom Recognizer 3: Pakistan Phone
# Example: 03001234567
# -------------------------------

pk_phone_pattern = Pattern(
    name="pk_phone_pattern",
    regex=r"03[0-9]{9}",
    score=0.9
)

pk_phone_recognizer = PatternRecognizer(
    supported_entity="PK_PHONE",
    patterns=[pk_phone_pattern]
)

analyzer.registry.add_recognizer(pk_phone_recognizer)


# -------------------------------
# Custom Recognizer 4: API Token
# Example: api_abcdef123456
# -------------------------------

api_token_pattern = Pattern(
    name="api_token_pattern",
    regex=r"api_[A-Za-z0-9]{10,}",
    score=0.85
)

api_token_recognizer = PatternRecognizer(
    supported_entity="API_TOKEN",
    patterns=[api_token_pattern]
)

analyzer.registry.add_recognizer(api_token_recognizer)


# -------------------------------
# Context words for better scoring
# -------------------------------

context_words = ["phone", "contact", "call", "number"]


# -------------------------------
# Composite Detection
# -------------------------------

def composite_detection(results):

    entities = [r.entity_type for r in results]

    if "PERSON" in entities and "PHONE_NUMBER" in entities:
        return True

    if "PERSON" in entities and "PK_PHONE" in entities:
        return True

    return False


# -------------------------------
# Main PII Analysis Function
# -------------------------------

def analyze_pii(text):

    results = analyzer.analyze(
        text=text,
        language="en"
    )

    # Confidence calibration
    for r in results:
        if r.score < 0.5:
            r.score += 0.1

    # Context-based score boost
    for word in context_words:
        if word in text.lower():
            for r in results:
                r.score = min(r.score + 0.1, 1.0)

    # Composite detection (optional)
    composite_flag = composite_detection(results)

    # Anonymize detected entities
    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results
    )

    return results, anonymized.text