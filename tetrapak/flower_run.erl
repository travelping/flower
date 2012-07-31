-module(flower_run).

-task({"run:flower", "Start flower application"}).

run("run:flower", _) ->
	tetrapak:require("build:erlang"),
	application:start(sasl),
	application:start(gen_listener_tcp),
	application:start(regine),
	application:start(flower),
	ok.
