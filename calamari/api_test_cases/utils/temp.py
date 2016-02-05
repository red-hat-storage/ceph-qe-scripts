

def foo():
    name = 'r'
    assert name is not None, "got None"

try:
    foo()
except AssertionError, e:
    print e

