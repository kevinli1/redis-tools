cJSON.o: cJSON.c cJSON.h
pcap_packet.o: pcap_packet.c pcap_packet.h redis-tools.h \
  ./deps/libpcap/pcap.h ./deps/libpcap/pcap/pcap.h \
  ./deps/libpcap/pcap/bpf.h script.h ./deps/lua/src/lua.h \
  ./deps/lua/src/luaconf.h ./deps/lua/src/lauxlib.h \
  ./deps/lua/src/lualib.h utils.h script.h ./deps/libpcap/pcap/sll.h
script.o: script.c redis-tools.h pcap_packet.h ./deps/libpcap/pcap.h \
  ./deps/libpcap/pcap/pcap.h ./deps/libpcap/pcap/bpf.h script.h \
  ./deps/lua/src/lua.h ./deps/lua/src/luaconf.h \
  ./deps/lua/src/lauxlib.h ./deps/lua/src/lualib.h utils.h 
redis-tools.o: redis-tools.c redis-tools.h pcap_packet.h ./deps/libpcap/pcap.h \
  ./deps/libpcap/pcap/pcap.h ./deps/libpcap/pcap/bpf.h script.h \
  ./deps/lua/src/lua.h ./deps/lua/src/luaconf.h \
  ./deps/lua/src/lauxlib.h ./deps/lua/src/lualib.h utils.h \
  ./deps/libpcap/pcap/sll.h 
utils.o: utils.c ./deps/libpcap/pcap.h \
  ./deps/libpcap/pcap/pcap.h ./deps/libpcap/pcap/bpf.h utils.h
