(cd ../../src//tcp && rm *.log)
(cd ../../src/ssl && rm *.log && make clean && make)

make clean
make main_server
make main_client1
make main_client2