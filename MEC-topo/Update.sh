#!/bin/bash

cp -r ../../MEC-V2/MEC ./

rm -rf ./MEC-V2

mv ./MEC ./MEC-V2

git add .

git commit -m 'MEC-topo'

git push

