-module(capi_utils).

-export([logtag_process/2]).
-export([base64url_to_map/1]).
-export([map_to_base64url/1]).

-export([to_universal_time/1]).

-export([redact/2]).

-export([unwrap/1]).
-export([define/2]).

-spec logtag_process(atom(), any()) -> ok.

logtag_process(Key, Value) when is_atom(Key) ->
    % TODO preformat into binary?
    logger:update_process_metadata(#{Key => Value}).

-spec base64url_to_map(binary()) -> map() | no_return().
base64url_to_map(Base64) when is_binary(Base64) ->
    try jsx:decode(base64url:decode(Base64), [return_maps])
    catch
        Class:Reason ->
            _ = logger:debug("decoding base64 ~p to map failed with ~p:~p", [Base64, Class, Reason]),
            erlang:error(badarg)
    end.

-spec map_to_base64url(map()) -> binary() | no_return().
map_to_base64url(Map) when is_map(Map) ->
    try base64url:encode(jsx:encode(Map))
    catch
        Class:Reason ->
            _ = logger:debug("encoding map ~p to base64 failed with ~p:~p", [Map, Class, Reason]),
            erlang:error(badarg)
    end.

-spec redact(Subject :: binary(), Pattern :: binary()) -> Redacted :: binary().
redact(Subject, Pattern) ->
    case re:run(Subject, Pattern, [global, {capture, all_but_first, index}]) of
        {match, Captures} ->
            lists:foldl(fun redact_match/2, Subject, Captures);
        nomatch ->
            Subject
    end.

redact_match({S, Len}, Subject) ->
    <<Pre:S/binary, _:Len/binary, Rest/binary>> = Subject,
    <<Pre/binary, (binary:copy(<<"*">>, Len))/binary, Rest/binary>>;
redact_match([Capture], Message) ->
    redact_match(Capture, Message).

-spec to_universal_time(Timestamp :: binary()) -> TimestampUTC :: binary().
to_universal_time(Timestamp) ->
    Microsecs = genlib_rfc3339:parse(Timestamp, microsecond),
    genlib_rfc3339:format_relaxed(Microsecs, microsecond).

-spec unwrap(ok | {ok, Value} | {error, _Error}) ->
    Value | no_return().
unwrap(ok) ->
    ok;
unwrap({ok, Value}) ->
    Value;
unwrap({error, Error}) ->
    erlang:error({unwrap_error, Error}).

-spec define(undefined | T, T) -> T.
define(undefined, V) ->
    V;
define(V, _Default) ->
    V.

%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-spec test() -> _.

-spec to_universal_time_test() -> _.
to_universal_time_test() ->
    ?assertEqual(<<"2017-04-19T13:56:07Z">>,        to_universal_time(<<"2017-04-19T13:56:07Z">>)),
    ?assertEqual(<<"2017-04-19T13:56:07.530Z">>, to_universal_time(<<"2017-04-19T13:56:07.53Z">>)),
    ?assertEqual(<<"2017-04-19T10:36:07.530Z">>, to_universal_time(<<"2017-04-19T13:56:07.53+03:20">>)),
    ?assertEqual(<<"2017-04-19T17:16:07.530Z">>, to_universal_time(<<"2017-04-19T13:56:07.53-03:20">>)).

-spec redact_test() -> _.
redact_test() ->
    P1 = <<"^\\+\\d(\\d{1,10}?)\\d{2,4}$">>,
    ?assertEqual(<<"+7******3210">>, redact(<<"+79876543210">>, P1)),
    ?assertEqual(       <<"+1*11">>, redact(<<"+1111">>, P1)).

-endif.
