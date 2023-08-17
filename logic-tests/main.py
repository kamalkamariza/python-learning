
import io 
import json
import pandas as pd
import re
import os
from enum import Enum
from datetime import datetime
import imghdr

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
    def comprehension_test():
        a = {
            'key1': [1,2,3,4,5],
            'key2': [1,2,3],
            'key3': [1]
        }

        print([{k:len(a[k])} for k in a.keys()])

    def concatenate_test():
        a = {"name": "test"}
        b = {"age": 12}
        c = {**a, **b}
        print(a)
        print(b)
        print(c)

    concatenate_test()

def file_test():
    with open('texts/long_list_text.txt', 'r') as f:
        texts = f.read().split('\n')

    texts_df = pd.read_csv('texts/long_list_csv.csv')

    print(texts[1:6])
    print(texts_df[0:5])

def datetime_test():
    from datetime import datetime

    dt_string = "2023-07-27 10:50:15"
    print(dt_string)

    dt_obj = datetime.strptime(dt_string, '%Y-%m-%d %H:%M:%S')

    dt_ts = int(dt_obj.timestamp()*1000)
    gt_ts = 1671607395595

    print(len(str(gt_ts)), len(str(dt_ts)), gt_ts >= dt_ts)

def update_dob_current_file(path):
    df = pd.read_csv(path)
    df.fillna("", inplace=True)

    for idx, row in df.iterrows():
        national_id = row['national_id']
        date_of_birth = row.get("date_of_birth")
        dob_str = ""
        if not date_of_birth and national_id and re.search(r'^\d{6}-?\d{2}-?\d{4}$', national_id):
            dob = national_id[0:6]
            try:
                dob_str = datetime.strptime(dob, '%y%m%d').strftime('%Y-%m-%d')
            except:
                dob_str = "0000-00-00"
        
        elif not date_of_birth and national_id:
            dob_str = "0000-00-00"

        df.at[idx, 'date_of_birth'] = dob_str

    df.to_csv(os.path.join('./', os.path.basename(path)), index=False)

def regex_test():
    state = 'bandar sri permaisuri'
    address = 'bandar lahad sri selangor permaisuri'
    state_words = state.split()
    regex_expression = 1
    # pattern = re.compile(regex_expression)
    match = re.match(r'{}'.format(r'.*'.join(state_words)),address)

    print(state)
    print(address)
    print(regex_expression)
    print(match)

def regex_test2():
    number = '5492 981 5243'
    expr = r'\b\d{3,4}\s\d{3,4}\s\d{3,4}\b'
    match = re.search(expr, number)
    print(match)
    print(expr)

def list_test():
    a = [
        {'class': 1, 'confidence': 0.9, 'text':'test1'},
        {'class': 2, 'confidence': 0.2, 'text':'test2'},
        {'class': 3, 'confidence': 0.4, 'text':'test3'},
        {'class': 4, 'confidence': 0.6, 'text':'test4'},
    ]

    b = [{dict['class']:{"confidence":dict['confidence'], "text":dict["text"]}} for dict in a]
    print(b)

def test_filename_extension():
    path = 'images/502653_247778.jpg'
    bytes = open(path, 'rb')
    print(imghdr.what(bytes))

    a = "filename.jpg"
    b = os.path.splitext(a)
    print(b)
    new_filename = b[0] + ".txt"
    print(new_filename)

if __name__ == "__main__":
    dict_test()