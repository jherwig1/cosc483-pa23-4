all: driver integrity

driver: driver.cpp ecb.o cbc.o ctr.o
	g++ -g -o driver ecb.o cbc.o ctr.o driver.cpp -lcrypto -lssl
integrity: integrity.cpp ecb.o cbc.o
	g++ -o integrity ecb.o cbc.o integrity.cpp -lcrypto -lssl
ecb.o: ecb.cpp
	g++ -g -c -o ecb.o ecb.cpp -lcrypto -lssl
cbc.o: cbc.cpp cbc.h
	g++ -g -c -o cbc.o cbc.cpp
ctr.o: ctr.cpp ctr.h cbc.h
	g++ -g -c -o ctr.o ctr.cpp
clean:
	rm *.o driver
