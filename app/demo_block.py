"""Intentional SAST demo fixture. Never imported or executed by the API."""


def unsafe_demo(expression):
    return eval(expression)
