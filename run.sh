#!/bin/bash

python3 ./keyphraseExtract.py 
python3 keyphraseExtract_check.py

# now using structured json so these are not required:
#python3 json_fix.py
#python3 json_fix.py --copy-back

python3 merge_jsons2all.py
python3 move2cve_dir_hash.py