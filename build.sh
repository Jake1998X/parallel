cd libipt
gcc -c -DPT_VERSION_MAJOR=2 -DPT_VERSION_MINOR=0 -DPT_VERSION_PATCH=0 -DPT_VERSION_BUILD="0" -DPT_VERSION_EXT="" -DFEATURE_THREADS ./src/*.c -I ./internal/include -I ./include/ -I ../include
mv *.o ../
cd ..
cd pevent
gcc -c ./src/*.c -I ./include/ -I ../libipt/include
mv *.o ../
cd ..
cd sideband
gcc -c ./src/*.c -I ./include/ -I ./internal/include/ -I../libipt/include/ -I ../pevent/include -I ../include
mv *.o ../
cd ..
cd profiler
gcc -c ./src/*.c -I ./include -I ./internal/include -I ../libipt/include -I ../include
mv *.o ../
cd ..
gcc -c pt2_decoder.c -I libipt/internal/include/ -I libipt/include/ -I sideband/include/ -I profiler/include/ -I ./include
gcc -o pt2_decoder *.o -lbfd -lpthread
rm *.o
