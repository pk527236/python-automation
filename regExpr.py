import re

text="Hello, my email is example@example.com and my phone number is 123-456-7890."
# Regular expression for matching email addresses

email_pattern = r'@example'

email_matches1 = re.findall(email_pattern, text)
# email_matches2=re.match(email_pattern,"phone")

# print(email_matches2.group())

text = "The quick brown fox"
pattern = r"quick"
#match will match from the initial staring so here the output is no match..search will search for the entire string....
match = re.match(pattern, text)
if match:
    print("Match found:", match.group())
else:
    print("No match")