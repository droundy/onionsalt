all: testing-flags/test.c paper/onionsalt.bbl tests/null.test tests/encrypt-encrypted-same-nonce.test tests/encrypt-decrypt.test tests/authentication.test tests/onion-box.test tests/unpeel-onion.test

testing-flags/test.c : configure.py
	python3 configure.py > .fac

lib/fontList.py3k.cache paper/onion-decryption.pdf paper/onion-encryption.pdf : paper paper/create-figures.py
	cd paper && python3 create-figures.py

paper/onionsalt.aux paper/onionsalt.bbl paper/onionsalt.blg paper/onionsalt.log paper/onionsalt.pdf paper/onionsaltNotes.bib : paper/onion-decryption.pdf paper/onion-encryption.pdf paper/onionsalt.bib paper/onionsalt.tex src/onionsalt.c src/onionsalt.h
	cd paper && pdflatex onionsalt.tex && bibtex onionsalt && pdflatex onionsalt.tex && pdflatex onionsalt.tex

src/tweetnacl.o : src/tweetnacl.c src/tweetnacl.h
	cd src && gcc ${CFLAGS} -std=c99 -O2 -g -o tweetnacl.o -c tweetnacl.c

src/randombytes.o : src/randombytes.c
	cd src && gcc ${CFLAGS} -std=c99 -O2 -g -o randombytes.o -c randombytes.c

src/onionsalt.o : src/onionsalt.c src/onionsalt.h src/tweetnacl.h
	cd src && gcc ${CFLAGS} -std=c99 -O2 -g -o onionsalt.o -c onionsalt.c

tests/null.o : src/tweetnacl.h tests/null.c
	cd tests && gcc ${CFLAGS} -std=c99 -O2 -g -I../src -o null.o -c null.c

tests/null.test : src/onionsalt.o src/randombytes.o src/tweetnacl.o tests/null.o
	gcc ${LDFLAGS} -O2 -g -o tests/null.test tests/null.o src/tweetnacl.o src/randombytes.o src/onionsalt.o

tests/encrypt-encrypted-same-nonce.o : src/tweetnacl.h tests/encrypt-encrypted-same-nonce.c
	cd tests && gcc ${CFLAGS} -std=c99 -O2 -g -I../src -o encrypt-encrypted-same-nonce.o -c encrypt-encrypted-same-nonce.c

tests/encrypt-encrypted-same-nonce.test : src/onionsalt.o src/randombytes.o src/tweetnacl.o tests/encrypt-encrypted-same-nonce.o
	gcc ${LDFLAGS} -O2 -g -o tests/encrypt-encrypted-same-nonce.test tests/encrypt-encrypted-same-nonce.o src/tweetnacl.o src/randombytes.o src/onionsalt.o

tests/encrypt-decrypt.o : src/tweetnacl.h tests/encrypt-decrypt.c
	cd tests && gcc ${CFLAGS} -std=c99 -O2 -g -I../src -o encrypt-decrypt.o -c encrypt-decrypt.c

tests/encrypt-decrypt.test : src/onionsalt.o src/randombytes.o src/tweetnacl.o tests/encrypt-decrypt.o
	gcc ${LDFLAGS} -O2 -g -o tests/encrypt-decrypt.test tests/encrypt-decrypt.o src/tweetnacl.o src/randombytes.o src/onionsalt.o

tests/authentication.o : src/tweetnacl.h tests/authentication.c
	cd tests && gcc ${CFLAGS} -std=c99 -O2 -g -I../src -o authentication.o -c authentication.c

tests/authentication.test : src/onionsalt.o src/randombytes.o src/tweetnacl.o tests/authentication.o
	gcc ${LDFLAGS} -O2 -g -o tests/authentication.test tests/authentication.o src/tweetnacl.o src/randombytes.o src/onionsalt.o

tests/onion-box.o : src/onionsalt.h src/tweetnacl.h tests/onion-box.c
	cd tests && gcc ${CFLAGS} -std=c99 -O2 -g -I../src -o onion-box.o -c onion-box.c

tests/onion-box.test : src/onionsalt.o src/randombytes.o src/tweetnacl.o tests/onion-box.o
	gcc ${LDFLAGS} -O2 -g -o tests/onion-box.test tests/onion-box.o src/tweetnacl.o src/randombytes.o src/onionsalt.o

tests/unpeel-onion.o : src/onionsalt.h src/tweetnacl.h tests/unpeel-onion.c
	cd tests && gcc ${CFLAGS} -std=c99 -O2 -g -I../src -o unpeel-onion.o -c unpeel-onion.c

tests/unpeel-onion.test : src/onionsalt.o src/randombytes.o src/tweetnacl.o tests/unpeel-onion.o
	gcc ${LDFLAGS} -O2 -g -o tests/unpeel-onion.test tests/unpeel-onion.o src/tweetnacl.o src/randombytes.o src/onionsalt.o

