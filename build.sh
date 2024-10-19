pushd hen && make clean && make && popd && bin2c -H include/hen.h -G HEN_H hen/hen.bin && make clean && make
