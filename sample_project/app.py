import os
import subprocess

command = input("Enter command: ")
user_code = input("Enter Python code: ")

os.system(command)
eval(user_code)

safe_name = input("Enter your name: ")
print(safe_name)

password = "admin123"
api_key = "abc-123"

# os.system(command)