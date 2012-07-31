%% counter for flower datapath
-record(flower_datapath_counter, {
		  raw_packets              = 0 :: non_neg_integer(),
		  unknown                  = 0 :: non_neg_integer(),
		  hello                    = 0 :: non_neg_integer(),
		  error                    = 0 :: non_neg_integer(),
		  echo_request             = 0 :: non_neg_integer(),
		  echo_reply               = 0 :: non_neg_integer(),
		  vendor                   = 0 :: non_neg_integer(),
		  features_request         = 0 :: non_neg_integer(),
		  features_reply           = 0 :: non_neg_integer(),
		  get_config_request       = 0 :: non_neg_integer(),
		  get_config_reply         = 0 :: non_neg_integer(),
		  set_config               = 0 :: non_neg_integer(),
		  packet_in                = 0 :: non_neg_integer(),
		  flow_removed             = 0 :: non_neg_integer(),
		  port_status              = 0 :: non_neg_integer(),
		  packet_out               = 0 :: non_neg_integer(),
		  flow_mod                 = 0 :: non_neg_integer(),
		  port_mod                 = 0 :: non_neg_integer(),
		  stats_request            = 0 :: non_neg_integer(),
		  stats_reply              = 0 :: non_neg_integer(),
		  barrier_request          = 0 :: non_neg_integer(),
		  barrier_reply            = 0 :: non_neg_integer(),
		  queue_get_config_request = 0 :: non_neg_integer(),
		  queue_get_config_reply   = 0 :: non_neg_integer(),
		  role_request             = 0 :: non_neg_integer(),
		  role_reply               = 0 :: non_neg_integer()
		 }).

-record(flower_datapath_counters, {
		  send = #flower_datapath_counter{} :: #flower_datapath_counter{},
		  recv = #flower_datapath_counter{} :: #flower_datapath_counter{}
}).
