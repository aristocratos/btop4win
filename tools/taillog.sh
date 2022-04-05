#!/usr/bin/env bash
clear
tail -n 30 -F btop.log |grcat grc.conf
