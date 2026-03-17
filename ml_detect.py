from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from ml_data import malicious_texts
from ml_data import normal_texts

texts = malicious_texts + normal_texts
labels = [1]*len(malicious_texts) + [0]*len(normal_texts)

vectorizer = CountVectorizer(ngram_range=(1,2))
X = vectorizer.fit_transform(texts)

model = LogisticRegression()
model.fit(X, labels)

def ml_det(text):
    X_test = vectorizer.transform([text])
    return model.predict(X_test)[0]