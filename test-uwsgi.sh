#!/bin/bash

uwsgi --socket 0.0.0.0:5000 --protocol=http --enable-threads -w webadpw 
