#!/usr/bin/env bash

sudo rm /usr/bin/ppsc

sudo sed -i '/^# added by Pyposcn/d' ~/.bashrc
sudo sed -i '/^export PYPOSCN_SYMLINK=/d' ~/.bashrc
sudo sed -i '/^export PYPOSCN_LOCATION=/d' ~/.bashrc


sudo rm -f ./pyposcn.sh
