from enum import Enum

class Color(Enum):
    RED = '1'
    GREEN = '2'
    BLUE = '3'

print(Color('1').name)
print(Color['RED'].value)