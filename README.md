FlowER - a Erlang OpenFlow development platform
===============================================

FlowER is a framework and a set of helper libraries to
develop OpenFlow controllers in Erlang.

Installation
------------

FlowER is build for deployment model that packages each Erlang
application either as RPM or DEB package. Dependencie resolution
is done at install time and at build time to the package management
tools. For manual building, the required dependencies therefore have to be
installed manually.

### Dependencies:

#### Build Tool:
- tetrapak (<http://github.com/fjl/tetrapak>)

#### Support Appplications:
- gen\_listener\_tcp (<http://github.com/travelping/gen_listener_tcp>)
- regine (<http://github.com/travelping/regine>)

Building
--------

Run tetrapak build:

    $ tetrapak build
    == tetrapak:boot =================
    Compiling tetrapak/flower_run.erl
    == build:erlang ==================
    Compiling src/flower_component_sup.erl
    Compiling src/flower_app.erl
    Compiling src/flower_datapath.erl
    Compiling src/flower_icmp.erl
    Compiling src/flower_datapath_sup.erl
    Compiling src/flower_event.erl
    Compiling src/lrulist.erl
    Compiling src/flower_match.erl
    Compiling src/flower_arp.erl
    Compiling src/flower_packet.erl
    Compiling src/flower_nib4.erl
    Compiling src/flower_tcp_socket.erl
    Compiling src/flower_tools.erl
    Compiling src/flower_simple_switch.erl
    Compiling src/flower_mac_learning.erl
    Compiling src/flower_dispatcher.erl
    Compiling src/flower_flow.erl
    Compiling src/flower_sup.erl

Sample Switch
-------------

flower_simple_switch is a very basic Layer 2 learning switch. It listens
for connection from OpenFlow datapath elements on localhost:6633.

Run it like this:

    $ erl -pa ebin
    Erlang R15B (erts-5.9) [source] [64-bit] [smp:2:2] [async-threads:0] [hipe] [kernel-poll:false]
    
    Eshell V5.9  (abort with ^G)
    1> application:start(sasl),
    1> application:start(gen_listener_tcp),
    1> application:start(regine),
    1> application:start(flower).          
    2> flower_simple_switch:start_link().
    
