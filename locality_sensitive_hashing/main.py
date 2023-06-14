'''
    From pinecone
    https://www.pinecone.io/learn/locality-sensitive-hashing/
'''

import requests
import pandas as pd
import io
import numpy as np
from utils import build_shingles, build_vocab, one_hot, minhash_arr, get_signature, jaccard, LSH, probability, normalize
from sklearn.metrics.pairwise import cosine_similarity
import json

SHINGLE_SIZE = 8 
SUB_VECTORS_SIZE = 20
MIN_HASH_FUNCTIONS = 100

# url = "https://raw.githubusercontent.com/brmson/dataset-sts/master/data/sts/sick2014/SICK_train.txt"
# text = requests.get(url).text

# data = pd.read_csv(io.StringIO(text), sep='\t')
# print(data.head())
# sentences = data['sentence_A'].tolist()[:2]

user_a = json.loads(json.loads(open('./ocr_files/536435_260486.txt', 'r').read())).get('fullTextAnnotation').get('text').replace('\n', ' ')
user_b = json.loads(json.loads(open('./ocr_files/536450_260492.txt', 'r').read())).get('fullTextAnnotation').get('text').replace('\n', ' ')
user_c = json.loads(open('./ocr_files/500376_246922.txt', 'r').read()).get('fullTextAnnotation').get('text').replace('\n', ' ')

print(user_a)
print(user_b)

sentences = [user_b, user_c]
print(sentences)

# build shingles
shingles = []
for sentence in sentences:
    shingles.append(build_shingles(sentence, SHINGLE_SIZE))
print(shingles)

# build vocab
vocab = build_vocab(shingles)
print(vocab)

# one-hot encode our shingles
shingles_1hot = []
for shingle_set in shingles:
    shingles_1hot.append(one_hot(shingle_set, vocab))
# print(shingles_1hot)
# print(np.array(shingles_1hot).shape)

# stack into single numpy array
shingles_1hot = np.stack(shingles_1hot)
# print(shingles_1hot.shape)

arr = minhash_arr(vocab, MIN_HASH_FUNCTIONS)
# print(arr.shape)

signatures = []
for vector in shingles_1hot:
    signatures.append(get_signature(arr, vector))

# merge signatures into single array
signatures = np.stack(signatures)
# print(signatures, signatures.shape)

lsh = LSH(SUB_VECTORS_SIZE)

for signature in signatures:
    lsh.add_hash(signature)
# print(lsh.buckets)

candidate_pairs = lsh.check_candidates()
print(len(candidate_pairs))
print(jaccard(set(signatures[0]), set(signatures[1])))
print(cosine_similarity([signatures[0]], [signatures[1]])[0][0])

pairs = pd.DataFrame({
    'x': [],
    'y': [],
    'jaccard': [],
    'cosine': [],
    'candidate': []
})

data_len = shingles_1hot.shape[0]
chosen = set()
# take random sample of pairs
sample_size = 50_000
for _ in range(sample_size):
    x, y = np.random.choice(data_len, 2)
    if x == y or (x, y) in chosen: continue
    chosen.add((x, y))
    vector_x = signatures[x]
    vector_y = signatures[y]
    candidate = 1 if (x, y) in candidate_pairs else 0
    cosine = cosine_similarity([vector_x], [vector_y])[0][0]
    pairs = pairs.append({
            'x': x,
            'y': y,
            'jaccard': jaccard(set(vector_x), set(vector_y)),
            'cosine': cosine,
            'candidate': candidate
        }, ignore_index=True)

# add a normalized cosine column for better alignment
cos_min = pairs['cosine'].min()
cos_max = pairs['cosine'].max()
pairs['cosine_norm'] = (pairs['cosine'] - cos_min) / (cos_max - cos_min)

# print(pairs)

b = SUB_VECTORS_SIZE
r = int(MIN_HASH_FUNCTIONS / SUB_VECTORS_SIZE)
s_scores = np.arange(0.01, 1, 0.01)
P_scores = [probability(s, r, b) for s in s_scores]

# print(s_scores)
# print(P_scores)