if [[ $a == 0 ]] ; then
rm -rf libbacktrace
a=$? ; else a=1 ; fi
if [[ $a == 0 ]] ; then
git clone https://github.com/ianlancetaylor/libbacktrace.git
a=$? ; else a=1 ; fi
if [[ $a == 0 ]] ; then
cd libbacktrace
a=$? ; else a=1 ; fi
if [[ $a == 0 ]] ; then
./configure
a=$? ; else a=1 ; fi
if [[ $a == 0 ]] ; then
make
a=$? ; else a=1 ; fi
if [[ $a == 0 ]] ; then
make check
a=$? ; else a=1 ; fi
if [[ $a == 0 ]] ; then
cd ../
a=$? ; else a=1 ; fi
