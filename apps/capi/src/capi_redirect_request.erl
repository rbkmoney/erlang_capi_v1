-module(capi_redirect_request).

-define(INVOICE_TEMPLATE_PATH, <<"/v2/processing/invoice-templates">>).
-export([process_request/4]).

-spec process_request(
    OperationID :: swag_server:operation_id(),
    Req :: swag_server:object(),
    ReqCtx :: swag_server:request_context(),
    HandlerOpts :: swag_server:handler_opts(_)
) -> {ok | error, swag_server:response()}.
process_request('CreateInvoiceTemplate', Req, ReqCtx0, _HandlerOpts) ->
    Params = encode_params(#{<<"InvoiceTemplateCreateParams">> => create_request_params(Req)}),
    Path = ?INVOICE_TEMPLATE_PATH,
    Url = get_url_api(Path),
    case do_request(post, Url, Params, ReqCtx0) of
        {ok, 201, BodyBin} ->
            Json = jsx:decode(BodyBin),
            #{
                <<"invoiceTemplate">> := InvoiceTemplate
            } = Json,
            Response = genlib_map:compact(Json#{<<"invoiceTemplate">> => create_response(InvoiceTemplate)}),
            {ok, {201, #{}, Response}};
        {error, {bad_params, Body}} ->
            Response = jsx:decode(Body),
            {ok, {400, #{}, Response}};
        {error, unauthorized_operation} ->
            {error, {401, #{}, #{<<"message">> => genlib:to_binary(<<"Unauthorized operation">>)}}};
        {error, Error} ->
            throw(Error)
    end;
process_request('GetInvoiceTemplateByID', Req, ReqCtx0, _HandlerOpts) ->
    TemplateID = maps:get(invoiceTemplateID, Req),
    Path = <<?INVOICE_TEMPLATE_PATH/binary, "/", TemplateID/binary>>,
    Url = get_url_api(Path),
    case do_request(get, Url, <<>>, ReqCtx0) of
        {ok, 200, BodyBin} ->
            Body = jsx:decode(BodyBin),
            Response = genlib_map:compact(create_response(Body)),
            {ok, {200, #{}, Response}};
        {error, unauthorized_operation} ->
            {error, {401, #{}, #{<<"message">> => genlib:to_binary(<<"Unauthorized operation">>)}}};
        {error, {not_found, Response}} ->
            {error, {404, #{}, Response}};
        {error, Error} ->
            throw(Error)
    end;
process_request('UpdateInvoiceTemplate', Req, ReqCtx0, _HandlerOpts) ->
    TemplateID = maps:get(invoiceTemplateID, Req),
    Path = <<?INVOICE_TEMPLATE_PATH/binary, "/", TemplateID/binary>>,
    Url = get_url_api(Path),
    Params = encode_params(#{<<"InvoiceTemplateUpdateParams">> => update_request_params(Req)}),
    case do_request(put, Url, Params, ReqCtx0) of
        {ok, 200, BodyBin} ->
            Body = jsx:decode(BodyBin),
            Response = genlib_map:compact(create_response(Body)),
            {ok, {200, #{}, Response}};
        {error, unauthorized_operation} ->
            {error, {401, #{}, #{<<"message">> => genlib:to_binary(<<"Unauthorized operation">>)}}};
        {error, {not_found, Response}} ->
            {error, {404, #{}, Response}};
        {error, Error} ->
            throw(Error)
    end;
process_request('DeleteInvoiceTemplate', Req, ReqCtx0, _HandlerOpts) ->
    TemplateID = maps:get(invoiceTemplateID, Req),
    Path = <<?PATH/binary, "/", TemplateID/binary>>,
    Url = get_url_api(Path),
    case do_request(delete, Url, <<>>, ReqCtx0) of
        {ok, 204, _} ->
            {ok, {204, #{}, undefined}};
        {error, {bad_params, Body}} ->
            Response = jsx:decode(Body),
            {ok, {400, #{}, Response}};
        {error, unauthorized_operation} ->
            {error, {401, #{}, #{<<"message">> => genlib:to_binary(<<"Unauthorized operation">>)}}};
        {error, {not_found, Response}} ->
            {error, {404, #{}, Response}};
        {error, Error} ->
            throw(Error)
    end;
process_request('CreateInvoiceWithTemplate', Req, ReqCtx0, _HandlerOpts) ->
    TemplateID = maps:get(invoiceTemplateID, Req),
    Params = encode_params(#{<<"InvoiceParamsWithTemplate">> => create_invoice_request_params(Req)}),
    Path = <<?PATH/binary, "/", TemplateID/binary, "/invoices">>,
    Url = get_url_api(Path),
    case do_request(post, Url, Params, ReqCtx0) of
        {ok, 201, Response} ->
            {ok, {201, #{}, jsx:decode(Response)}};
        {error, {bad_params, Body}} ->
            Response = jsx:decode(Body),
            {ok, {400, #{}, Response}};
        {error, unauthorized_operation} ->
            {error, {401, #{}, #{<<"message">> => genlib:to_binary(<<"Unauthorized operation">>)}}};
        {error, {not_found, Response}} ->
            {error, {404, #{}, Response}};
        {error, Error} ->
            throw(Error)
    end;
process_request('GetInvoicePaymentMethodsByTemplateID', Req, ReqCtx0, _) ->
    TemplateID = maps:get(invoiceTemplateID, Req),
    Path = <<?PATH/binary, "/", TemplateID/binary, "/payment-methods">>,
    Url = get_url_api(Path),
    case do_request(get, Url, <<>>, ReqCtx0) of
        {ok, 200, Response} ->
            {ok, {200, #{}, jsx:decode(Response)}};
        {error, unauthorized_operation} ->
            {error, {401, #{}, #{<<"message">> => genlib:to_binary(<<"Unauthorized operation">>)}}};
        {error, {not_found, Response}} ->
            {error, {404, #{}, Response}};
        {error, Error} ->
            throw(Error)
    end.

do_request(Method, Url, Params, ReqCtx0) ->
    Headers = get_request_headers(ReqCtx0),
    Options = get_request_options(),
    handle_result(hackney:request(Method, Url, Headers, Params, Options)).

handle_result({ok, 200, _Headers, Ref}) ->
    {ok, Body} = get_body(hackney:body(Ref)),
    {ok, 200, Body};
handle_result({ok, 201, _Headers, Ref}) ->
    {ok, Body} = get_body(hackney:body(Ref)),
    {ok, 201, Body};
handle_result({ok, 204, _Headers, _Ref}) ->
    % {ok, Body} = get_body(hackney:body(Ref)),
    {ok, 204, <<>>};
handle_result({ok, 400, _, Ref}) ->
    {ok, Body} = get_body(hackney:body(Ref)),
    {error, {bad_params, Body}};
handle_result({ok, 401, _, _}) ->
    {error, unauthorized_operation};
handle_result({ok, 404, _, Ref}) ->
    {ok, Body} = get_body(hackney:body(Ref)),
    {error, {not_found, Body}};
handle_result({ok, Code, _Headers, Ref}) ->
    _ = hackney:skip_body(Ref),
    {error, {http_code_unexpected, Code}};
handle_result({error, {closed, _}}) ->
    {error, {result_unknown, partial_response}};
handle_result({error, Reason}) when
    Reason =:= timeout;
    Reason =:= econnaborted;
    Reason =:= enetreset;
    Reason =:= econnreset;
    Reason =:= eshutdown;
    Reason =:= etimedout;
    Reason =:= closed
->
    {error, {result_unknown, Reason}};
handle_result({error, Reason}) when
    Reason =:= econnrefused;
    Reason =:= connect_timeout;
    Reason =:= checkout_timeout;
    Reason =:= enetdown;
    Reason =:= enetunreach
->
    {error, {resource_unavailable, Reason}}.

get_body(B = {ok, _}) -> B;
get_body({error, Reason}) -> {error, {http_body, Reason}}.

get_url_api(Path) ->
    {ok, Opts} = application:get_env(capi, payment_api_v2),
    Url = maps:get(url, Opts),
    <<Url/binary, Path/binary>>.

get_request_options() ->
    {ok, Opts} = application:get_env(capi, payment_api_v2),
    maps:get(request_opts, Opts, []).

get_request_headers(ReqCtx) ->
    Req = maps:get(cowboy_req, ReqCtx),
    Headers0 = maps:get(headers, Req),
    Headers1 = lists:foldl(
        fun(Header, Acc) ->
            maps:remove(Header, Acc)
        end,
        Headers0,
        [<<"content-length">>, <<"accept">>, <<"accept-charset">>]
    ),
    maps:to_list(Headers1).

encode_params(Params) ->
    jsx:encode(Params).

create_request_params(#{'InvoiceTemplateCreateParams' := Params} = _Req) ->
    Details = #{
        <<"templateType">> => <<"InvoiceTemplateSingleLine">>,
        <<"product">> => maps:get(<<"product">>, Params),
        <<"price">> => convert_cost_to_price(maps:get(<<"cost">>, Params))
    },
    genlib_map:compact(#{
        <<"shopID">> => maps:get(<<"shopID">>, Params),
        <<"description">> => maps:get(<<"description">>, Params, undefined),
        <<"lifetime">> => maps:get(<<"lifetime">>, Params),
        <<"details">> => Details,
        <<"metadata">> => maps:get(<<"metadata">>, Params, undefined)
    }).

update_request_params(#{'InvoiceTemplateUpdateParams' := Params}) ->
    Details =
        case maps:get(<<"cost">>, Params, undefined) of
            undefined ->
                undefined;
            _Cost ->
                #{
                    <<"templateType">> => <<"InvoiceTemplateSingleLine">>,
                    <<"product">> => maps:get(<<"product">>, Params),
                    <<"price">> => convert_cost_to_price(maps:get(<<"cost">>, Params))
                }
        end,
    genlib_map:compact(#{
        <<"shopID">> => maps:get(<<"shopID">>, Params, undefined),
        <<"description">> => maps:get(<<"description">>, Params, undefined),
        <<"lifetime">> => maps:get(<<"lifetime">>, Params, undefined),
        <<"details">> => Details,
        <<"metadata">> => maps:get(<<"metadata">>, Params, undefined)
    }).

create_invoice_request_params(#{'InvoiceParamsWithTemplate' := Params}) ->
    Params.

create_response(InvoiceTemplate0) ->
    #{<<"templateType">> := <<"InvoiceTemplateSingleLine">>} = Details = maps:get(<<"details">>, InvoiceTemplate0),
    Product = maps:get(<<"product">>, Details),
    Cost = convert_price_to_cost(maps:get(<<"price">>, Details)),
    InvoiceTemplate1 = maps:remove(<<"details">>, InvoiceTemplate0),
    InvoiceTemplate2 = maps:remove(<<"taxMode">>, InvoiceTemplate1),
    InvoiceTemplate = InvoiceTemplate2#{
        <<"product">> => Product,
        <<"cost">> => Cost
    },
    InvoiceTemplate.

convert_cost_to_price(#{<<"invoiceTemplateCostType">> := <<"InvoiceTemplateCostRange">>} = CostParams) ->
    PriceParams = maps:remove(<<"invoiceTemplateCostType">>, CostParams),
    PriceParams#{
        <<"costType">> => <<"InvoiceTemplateLineCostRange">>
    };
convert_cost_to_price(#{<<"invoiceTemplateCostType">> := <<"InvoiceTemplateCostFixed">>} = CostParams) ->
    PriceParams = maps:remove(<<"invoiceTemplateCostType">>, CostParams),
    PriceParams#{
        <<"costType">> => <<"InvoiceTemplateLineCostFixed">>
    };
convert_cost_to_price(#{<<"invoiceTemplateCostType">> := <<"InvoiceTemplateCostUnlim">>}) ->
    #{
        <<"costType">> => <<"InvoiceTemplateLineCostUnlim">>
    }.

convert_price_to_cost(#{<<"costType">> := <<"InvoiceTemplateLineCostRange">>} = PriceParams) ->
    CostParams = maps:remove(<<"costType">>, PriceParams),
    CostParams#{
        <<"invoiceTemplateCostType">> => <<"InvoiceTemplateCostRange">>
    };
convert_price_to_cost(#{<<"costType">> := <<"InvoiceTemplateLineCostFixed">>} = PriceParams) ->
    CostParams = maps:remove(<<"costType">>, PriceParams),
    CostParams#{
        <<"invoiceTemplateCostType">> => <<"InvoiceTemplateCostFixed">>
    };
convert_price_to_cost(#{<<"costType">> := <<"InvoiceTemplateLineCostUnlim">>}) ->
    #{<<"invoiceTemplateCostType">> => <<"InvoiceTemplateCostUnlim">>}.
