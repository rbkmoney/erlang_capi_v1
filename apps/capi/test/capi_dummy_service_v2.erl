-module(capi_dummy_service_v2).

-include_lib("eunit/include/eunit.hrl").
-include_lib("capi_dummy_data.hrl").

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
        {'_', [{'_', ?MODULE, []}]}
    ]),
    {ok, _} = cowboy:start_clear(
        my_http_listener,
        [{port, Port}],
        #{env => #{dispatch => Dispatch}}
    ),
    ok.

-spec init(any(), any()) -> {ok, any(), any()}.

init(Req0, State) ->
    case get_method_url(Req0) of
        {<<"GET">>, <<"/v2/processing/invoice-templates/TEST">>} ->
            get_invoice_tmpl(Req0, State);
        {<<"GET">>, <<"/v2/processing/invoice-templates/TEST/payment-methods">>} ->
            Req1 = cowboy_req:reply(
                200,
                #{},
                jsx:encode([
                    #{
                        <<"method">> => <<"BankCard">>,
                        <<"paymentSystems">> => <<"visa">>
                    }
                ]),
                Req0
            ),
            {ok, Req1, State};
        {<<"POST">>, <<"/v2/processing/invoice-templates">>} ->
            create_invoice_tmpl(Req0, State);
        {<<"POST">>, <<"/v2/processing/invoice-templates/TEST/invoices">>} ->
            create_invoice(Req0, State);
        {<<"PUT">>, <<"/v2/processing/invoice-templates/TEST">>} ->
            get_invoice_tmpl(Req0, State);
        {<<"DELETE">>, _} ->
            Req1 = cowboy_req:reply(204, #{}, <<>>, Req0),
            {ok, Req1, State}
    end.

get_method_url(Req) ->
    Method = maps:get(method, Req),
    Url = maps:get(path, Req),
    {Method, Url}.

get_invoice_tmpl(Req0, State) ->
    Response = jsx:encode(#{
        <<"id">> => <<"1">>,
        <<"shopID">> => ?STRING,
        <<"lifetime">> => #{
            <<"days">> => 0,
            <<"months">> => 1,
            <<"years">> => 2
        },
        <<"details">> => #{
            <<"templateType">> => <<"InvoiceTemplateSingleLine">>,
            <<"product">> => ?STRING,
            <<"price">> => #{
                <<"costType">> => <<"InvoiceTemplateLineCostFixed">>,
                <<"currency">> => <<"RUB">>,
                <<"amount">> => 1000
            }
        }
    }),
    Req1 = cowboy_req:reply(
        200,
        #{<<"content-type">> => <<"application/json; charset=UTF-8">>},
        Response,
        Req0
    ),
    {ok, Req1, State}.

create_invoice_tmpl(Req0, State) ->
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

create_invoice(Req0, State) ->
    {ok, [{BodyBin, _}], Req1} = read_body_params(Req0),
    Params = jsx:decode(BodyBin),
    Response = jsx:encode(#{
        <<"invoice">> => Params#{
            <<"id">> => <<"1">>,
            <<"product">> => ?STRING,
            <<"shopID">> => ?STRING,
            <<"createdAt">> => ?TIMESTAMP,
            <<"dueDate">> => ?TIMESTAMP,
            <<"status">> => <<"unpaid">>
        },
        <<"invoiceAccessToken">> => #{
            <<"payload">> => <<"token">>
        }
    }),
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
