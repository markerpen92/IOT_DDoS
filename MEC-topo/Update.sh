#!/bin/bash

cp -r ../../MEC-V2/MEC ./

mv ./MEC ./MEC-V2

git add .

git commit -m 'MEC-topo'

git push

