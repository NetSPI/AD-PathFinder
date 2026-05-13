#!/bin/bash
clear
head -361 report_training.local/training.local_domain_audit.txt | awk '{print; fflush(); system("sleep 0.45")}'
