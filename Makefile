test:testudp.cpp
	g++ -o test testudp.cpp -fpermissive -g
clean:
	rm -f .o test
