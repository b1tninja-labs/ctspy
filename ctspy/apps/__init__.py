"""Composition that assembles core pieces and adds no protocol behaviour.

Importing from here says "I am assembling", which is the distinction the project cares about.
Nothing in this package may know how the wire format works: if it does, it belongs one level
up, cited against a document.
"""
