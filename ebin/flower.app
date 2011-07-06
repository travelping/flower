{application, flower,
  [{description,[]},
   {vsn,"1"},
   {registered,[]},
   {applications,[kernel,stdlib,sasl,gen_listener_tcp]},
   {mod,{flower_app,[]}},
   {env,[]},
   {modules,[flower_app,flower_component_sup,flower_datapath,
             flower_datapath_sup,flower_dispatcher,flower_event,flower_flow,
             flower_mac_learning,flower_match,flower_packet,
             flower_simple_switch,flower_sup,flower_tcp_socket,lrulist]}]
}.