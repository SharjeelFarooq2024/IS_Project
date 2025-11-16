import base64
import binascii
import hmac
import os
import re
from collections import Counter
from hashlib import sha256
from typing import Iterable, List

from dotenv import load_dotenv

load_dotenv()

_raw_key = os.getenv("HMAC_KEY")
if not _raw_key:
    raise ValueError("HMAC_KEY is missing from the environment. Add it to your .env file.")

try:
    HMAC_KEY = base64.urlsafe_b64decode(_raw_key)
except (binascii.Error, ValueError):
    HMAC_KEY = _raw_key.encode()


def normalize_keywords(raw: str | None) -> List[str]:
    if not raw:
        return []
    tokens: list[str] = []
    for part in [segment.strip() for segment in raw.replace('\n', ' ').split(',')]:
        if not part:
            continue
        for token in part.split():
            normalized = token.strip().lower()
            if normalized and normalized not in tokens:
                tokens.append(normalized)
    return tokens


def hash_keyword(keyword: str) -> str:
    normalized = keyword.strip().lower()
    digest = hmac.new(HMAC_KEY, normalized.encode(), sha256).hexdigest()
    return digest


def hash_keywords(keywords: Iterable[str]) -> List[str]:
    return [hash_keyword(keyword) for keyword in keywords]


STOPWORDS = {
    'a',
    'an',
    'and',
    'are',
    'as',
    'at',
    'be',
    'by',
    'for',
    'from',
    'how',
    'in',
    'is',
    'it',
    'of',
    'on',
    'or',
    'that',
    'the',
    'this',
    'to',
    'was',
    'were',
    'will',
    'with',
}


def extract_keywords_from_text(text: str | None, limit: int = 12) -> List[str]:
    if not text:
        return []
    tokens = re.findall(r"[a-z0-9']+", text.lower())
    filtered = [token for token in tokens if len(token) > 2 and token not in STOPWORDS]
    if not filtered:
        return []
    ranked = [word for word, _ in Counter(filtered).most_common(limit)]
    return ranked
