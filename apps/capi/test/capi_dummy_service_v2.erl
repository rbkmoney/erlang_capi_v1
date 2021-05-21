-module(capi_dummy_service_v2).

-include_lib("eunit/include/eunit.hrl").

-export([
    start/1,
    init/2
]).

-export([test/0]).
-spec test() -> ok.
test() -> ok.

-spec start(integer()) -> ok.

start(Port) ->
    Dispatch = cowboy_router:compile([
        {'_', [{"/v2/processing/invoice-templates", ?MODULE, []}]}
    ]),
    {ok, _} = cowboy:start_clear(
        my_http_listener,
        [{port, Port}],
        #{env => #{dispatch => Dispatch}}
    ),
    ok.

-spec init(any(), any()) -> {ok, any(), any()}.

init(Req0, State) ->
    {ok, [{BodyBin, _}], Req1} = read_body_params(Req0),
    Body = jsx:decode(BodyBin),
    Response = get_response(Body),
    Req2 = cowboy_req:reply(
        201,
        #{<<"content-type">> => <<"application/json; charset=UTF-8">>},
        Response,
        Req1
    ),
    {ok, Req2, State}.

get_response(Body) ->
    jsx:encode(#{
        <<"invoiceTemplate">> => Body#{
            <<"id">> => <<"1">>
        },
        <<"invoiceTemplateAccessToken">> => #{
            <<"payload">> => <<"token">>
        }
    }).

-spec read_body_params(cowboy_req:req()) -> {ok, any(), cowboy_req:req()}.

read_body_params(Req) ->
    cowboy_req:read_urlencoded_body(Req).
