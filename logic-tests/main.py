
import io 
import json
from enum import Enum

def json_test():
    file_byte = io.BytesIO(open('images/502653_247778.txt', 'rb').read()).read()
    json_result = json.loads(file_byte)
    if not isinstance(json_result, dict):
        json_result = json.loads(json_result)

    print(json_result.get("textAnnotations", [{}])[0].get("description", ""))

def enum_test():
    class Color(Enum):
        RED = '1'
        GREEN = '2'
        BLUE = '3'

    print(Color('1').name)
    print(Color['RED'].value)

def dict_test():
    a = {
        'key1': [1,2,3,4,5],
        'key2': [1,2,3],
        'key3': [1]
    }

    print([{k:len(a[k])} for k in a.keys()])
    
if __name__ == "__main__":
    json_test()