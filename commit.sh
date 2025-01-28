#!/bin/bash

[ "$1" == "" ]   && echo "[ERROR] Require Comment" && exit 1
[ "$1" == "-m" ] && echo "[ERROR] Not -m option" && exit 1
git add .
git commit -m "$1"
git update-ref refs/heads/master HEAD
