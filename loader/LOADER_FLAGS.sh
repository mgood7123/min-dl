set -v
additional_flags="-w"
debug="-g3 -O0 $additional_flags"
compile="$debug -fPIC -c"
share="$debug -fPIC -shared"
link="$debug"
RE=readelf_.c
rm -rfv files
mkdir ./files
a=$?
