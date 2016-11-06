driver: driver.cpp ecb.o
	g++ -o driver ecb.o driver.cpp -lcrypto -lssl
ecb.o: ecb.cpp
	g++ -c -o ecb.o ecb.cpp -lcrypto -lssl
