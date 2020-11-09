#!/bin/bash
sudo make -j6
sudo make modules_install -j6
sudo make install
sudo shutdown
