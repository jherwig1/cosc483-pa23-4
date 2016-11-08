import random

string = ""
for i in range(2, random.randint(1, 5000) * 2, 2):
	string += random.choice(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'])
print string
	
