driver: driver.cpp ecb.o cbc.o
	g++ -o driver ecb.o cbc.o driver.cpp -lcrypto -lssl
ecb.o: ecb.cpp
	g++ -c -o ecb.o ecb.cpp -lcrypto -lssl
cbc.o: cbc.cpp cbc.h
	g++ -c -o cbc.o cbc.cpp
