nfqnl_test: nfqnl_test.c
	gcc -o nfqnl_test nfqnl_test.c -lnetfilter_queue
	sudo iptables -F
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
clean :
	rm -f nfqnl_test
