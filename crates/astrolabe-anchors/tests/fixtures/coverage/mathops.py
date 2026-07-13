def add(a, b):
    result = a + b
    return result


def subtract(a, b):
    result = a - b
    return result


def multiply(a, b):
    total = 0
    for _ in range(abs(b)):
        total += a
    if b < 0:
        total = -total
    return total


def divide(a, b):
    if b == 0:
        raise ValueError("division by zero")
    return a / b
