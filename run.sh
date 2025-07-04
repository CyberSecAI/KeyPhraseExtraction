#!/bin/bash

python3 keyphraseExtract_check.py
python3 json_fix.py
python3 json_fix.py --copy-back
python3 merge_jsons2all.py
python3 move2cve_dir_hash.py