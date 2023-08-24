#! /bin/bash
tmux send-keys -t docker-bind:0.1 'dig @172.20.0.2 +timeout=1 +tries=1 test'$1'.example' Enter
sleep 2
tmux capture-pane -t docker-bind:0.1 -pS - > dig_logs/run_$1.log
tmux send-keys -t docker-bind:0.1 -R Enter
tmux clear-history -t docker-bind:0.1
sleep 1
