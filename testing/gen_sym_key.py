import random

string = ""
for i in range(32):
	string += random.choice(['0', '1', '2', '3', '4', '5', '6', '7', 'a', 'b', 'c', 'd', 'e', 'f'])

print string
