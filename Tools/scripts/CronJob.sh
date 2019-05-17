#!/bin/bash
WD=$(pwd)
cd /home/noise
mkdir output
mkdir ingested

/home/noise/AsaCli/res/AttackSurfaceAnalyzerCli collect -a --no-filters --debug
/home/noise/AsaCli/res/AttackSurfaceAnalyzerCli export-collect --outputpath output --explodedoutput
/home/noise/AsaCli/res/AttackSurfaceAnalyzerCli config --trim-to-latest

cd /home/noise/output

for d in /home/noise/output/*
do
    cd "$d"
    FILES=*_*
    for f in $FILES
    do
        if [ $(wc -l $f | cut -d' ' -f1) -gt "0" ]; then
            #c=$(echo $f | cut -d'_' -f1)
            #un=$(uname)
            #s="_"
            #c="$un$s$c"
            c=$(uname)
	    p=$(cat /home/noise/CREDENTIAL)
            u=$(cat /home/noise/USER)
            echo "Adding $f's data to '$c' collection"
            mongoimport -h noise-mongodb.documents.azure.com:10255 --ssl -c $c -u $u -p $p --jsonArray $f
        else
            echo "Skipping $f"
        fi
    done
    cd /home/noise/output
    mv "$d" /home/noise/ingested/
    echo "Moving ingested directory $d"
done

cd $WD
