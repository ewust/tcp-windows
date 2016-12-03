#!/bin/bash

#scp censys-scratch-5:./tcp-windows2.out ./

cat tcp-windows*.out | awk '!cnts[$1]++' | awk -F' ' '{print $4}' | grep -v ',' | sort -n | cdf > windows.cdf
cat tcp-windows*.out | awk '!cnts[$1]++' | awk -F' ' '{print $2}' | grep -v ',' | sort -n | cdf > syn-ack-wins.cdf

gnuplot win.gnuplot
