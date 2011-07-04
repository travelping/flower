-ifdef(debug).

-define(DEBUG(X), ?DEBUG(X, [])).
-define(DEBUG(Fmt, Args),
    io:format("~p:~p -- " ++ Fmt, [?MODULE, ?LINE | Args])).

-else.

-define(DEBUG(X), ok).
-define(DEBUG(X, Args), ok).

-endif.
