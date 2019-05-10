#!/bin/bash
cd ~/AsaCli/

./AttackSurfaceAnalyzerCli collect -a
./AttackSurfaceAnalyzerCli export-collect --outputpath output --explodedoutput
./AttackSurfaceAnalyzerCli config --trim-to-latest

cd output

DIRS=$(ls -l | grep '^d' | rev | cut -d' ' -f1 | rev)
for d in $DIRS
do
    cd $d
    FILES=*_*
    for f in $FILES
    do
    if [ $(wc -l $f | cut -d' ' -f1) -gt "0" ]; then
        c=$(echo $f | cut -d'_' -f1)
        u=$(uname)
        c="$u_$c"
        p=$(cat ~/CREDENTIAL)
        u=$(cat ~/USER)
        echo "Adding $f's data to '$c' collection"
        mongoimport -h noise-mongodb.documents.azure.com:10255 --ssl -c $c -u $u -p $p --jsonArray $f
    fi
    done
    cd ..
    rm -rf $d
    echo "Deleting parsed directory $d"
done