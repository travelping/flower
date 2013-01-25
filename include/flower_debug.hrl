-ifdef(debug).

-define(DEBUG(FORMAT, DATA),
        io:format("~w(~B): " ++ (FORMAT) ++ "~n", [?MODULE, ?LINE | DATA])).
-define(DEBUG(FORMAT), ?DEBUG(FORMAT, [])).

-else.

-define(DEBUG(FORMAT, DATA), (false andalso (DATA) orelse ok)).
-define(DEBUG(FORMAT), ok).

-endif.
