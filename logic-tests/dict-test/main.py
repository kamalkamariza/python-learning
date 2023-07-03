
a = {
    'key1': [1,2,3,4,5],
    'key2': [1,2,3],
    'key3': [1]
}

print([{k:len(a[k])} for k in a.keys()])