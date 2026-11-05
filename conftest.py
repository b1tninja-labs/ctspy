"""Make the project root importable when pytest is run from anywhere.

The package lives at the repository root, so with this file present pytest inserts that root
on sys.path and importing the package works however the test command was invoked.
"""
