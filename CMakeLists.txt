# Generated by binpac_quickstart

include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro FTPDEMO)
	bro_plugin_cc(FTPDEMO.cc Plugin.cc)
	bro_plugin_bif(events.bif)
	bro_plugin_pac(ftpdemo.pac ftpdemo-analyzer.pac ftpdemo-protocol.pac)
bro_plugin_end()