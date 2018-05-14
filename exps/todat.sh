#!/bin/bash

EXP=$1


sed -e '331,335d; 1,6d; /^\[ ID/d; /^\[SUM/d; /^-/d; s/\-[1-9][0-9]*\.[0-9][0-9]//; s/\.[0-9][0-9]//; s/\]//;' iperf.exp$EXP.log | \
awk -v num=$EXP '{ rate = $7; if ($8 == "Gbits/sec") { rate = $7 * 1000}; if (NR%2 == 0) { print rate >> "exp"  num ".2.dat"} else {print rate >> "exp" num ".1.dat"}}'

#awk -F' ' '{ print $3, $7 ".0"}' | awk -v num="$EXP" '{if (NR%2 == 0) { print >> "exp" num ".2.dat"} else { print >> "exp" num ".1.dat"}}'
