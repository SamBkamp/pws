#!/bin/bash

rm pws
make CFLAGS=-fdump-rtl-expand
egypt *.expand | dot -Tpng -Gratio=0.5 -Nfontcolor=white -Ecolor=white -Ncolor=white -Gbgcolor=black  -o docs/callgraph.png
rm *.expand
