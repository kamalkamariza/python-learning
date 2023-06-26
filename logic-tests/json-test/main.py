
import io 
import json

file_byte = io.BytesIO(open('images/502653_247778.txt', 'rb').read()).read()
json_result = json.loads(file_byte)
if not isinstance(json_result, dict):
    json_result = json.loads(json_result)

print(json_result.get("textAnnotations", [{}])[0].get("description", ""))