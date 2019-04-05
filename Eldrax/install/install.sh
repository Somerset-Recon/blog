#!/bin/bash

if [[ -z "${GHIDRA_ROOT}" ]]; then
    echo  "GHIDRA_ROOT is not set :(" 
    exit
else
   GHIDRA_ROOT="$GHIDRA_ROOT"
   PYSCRIPT_PATH="Ghidra/Features/Python/ghidra_scripts"
   mv ../Eldrax.py "$GHIDRA_ROOT/$PYSCRIPT_PATH"
fi
