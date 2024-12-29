#!/usr/bin/sh

cd test
while true
do
cp ../test_bin infectme
#strace ./slotmachine
./slotmachine
mv infectme slotmachine
sleep 1
done
