-module(capi_auth).

-export([authorize_api_key/3]).
-export([init_provider/2]).
-export([authorize_operation/2]).

-export([issue_invoice_access_token/3]).
-export([issue_invoice_template_access_token/3]).
-export([issue_customer_access_token/3]).

-export([get_subject_id/1]).
-export([get_subject_email/1]).

-export([get_resource_hierarchy/0]).

-type claims() :: capi_authorizer_jwt:claims().
-type context() ::
    {auth_data, capi_token_keeper:auth_data()}
    | {legacy, {claims(), capi_authorizer_jwt:metadata()}}.

-type provider() ::
    {bouncer, capi_bouncer_context:fragments(), woody_context:ctx()}
    | {legacy, capi_acl:t()}.

-type resolution() ::
    allowed
    | forbidden.

-export_type([context/0]).
-export_type([provider/0]).
-export_type([resolution/0]).

-spec authorize_api_key(
    OperationID :: swag_server:operation_id(),
    ApiKey :: swag_server:api_key(),
    ReqContext :: swag_server:request_context()
) -> {true, Context :: context()} | false.
authorize_api_key(OperationID, ApiKey, ReqContext) ->
    case parse_api_key(ApiKey) of
        {ok, {Type, Credentials}} ->
            case authorize_api_key_type(Type, Credentials, ReqContext) of
                {ok, Context} ->
                    {true, Context};
                {error, Error} ->
                    _ = log_auth_error(OperationID, Error),
                    false
            end;
        {error, Error} ->
            _ = log_auth_error(OperationID, Error),
            false
    end.

log_auth_error(OperationID, Error) ->
    logger:info("API Key authorization failed for ~p due to ~p", [OperationID, Error]).

-spec parse_api_key(ApiKey :: swag_server:api_key()) ->
    {ok, {bearer, Credentials :: binary()}} | {error, Reason :: atom()}.
parse_api_key(ApiKey) ->
    case ApiKey of
        <<"Bearer ", Credentials/binary>> ->
            {ok, {bearer, Credentials}};
        _ ->
            {error, unsupported_auth_scheme}
    end.

-spec authorize_api_key_type(
    Type :: atom(),
    Credentials :: binary(),
    ReqContext :: swag_server:request_context()
) -> {ok, Context :: context()} | {error, Reason :: term()}.
authorize_api_key_type(bearer, Token, ReqContext) ->
    % NOTE
    % We are knowingly delegating actual request authorization to the logic handler
    % so we could gather more data to perform fine-grained access control.
    case get_authdata_by_token(Token, ReqContext) of
        {ok, AuthData} ->
            {ok, {auth_data, AuthData}};
        {error, _} ->
            case capi_authorizer_jwt:verify(Token) of
                {ok, TokenInfo} ->
                    {ok, {legacy, TokenInfo}};
                {error, _Reason} = Error ->
                    Error
            end
    end.

-spec get_authdata_by_token(
    Token :: binary(),
    ReqContext :: swag_server:request_context()
) -> {ok, capi_token_keeper:auth_data()} | {error, Reason :: term()}.
get_authdata_by_token(Token, ReqContext) ->
    capi_token_keeper:get_authdata_by_token(Token, make_source_context(ReqContext)).

-spec make_source_context(swag_server:request_context()) -> capi_token_keeper:token_source_context() | undefined.
make_source_context(#{cowboy_req := CowboyReq}) ->
    case cowboy_req:header(<<"origin">>, CowboyReq) of
        Origin when is_binary(Origin) ->
            #{request_origin => Origin};
        undefined ->
            undefined
    end.

%%

-spec init_provider(
    ReqCtx :: swag_server:request_context(),
    WoodyCtx :: woody_context:ctx()
) -> {ok, provider()} | {error, _Reason}.
init_provider(ReqCtx, WoodyCtx) ->
    % NOTE
    % We need to support both bouncer-based authorization as well as legacy ACL-based one. Non-zero
    % number of various access tokens will probably be in-flight at the time of service update
    % rollout. And if we ever receive such token it should be better to handle it through legacy
    % authz machinery, since we have no simple way to extract required bouncer context out of it.
    case capi_bouncer:gather_context_fragments(ReqCtx, WoodyCtx) of
        Fragments when Fragments /= undefined ->
            {ok, {bouncer, Fragments, WoodyCtx}};
        undefined ->
            init_legacy_provider(ReqCtx)
    end.

init_legacy_provider(ReqCtx) ->
    {legacy, {Claims, _}} = get_auth_context(ReqCtx),
    case capi_authorizer_jwt:get_acl(Claims) of
        {ok, ACL} ->
            {ok, {legacy, ACL}};
        {error, _} = Error ->
            Error;
        undefined ->
            {error, {missing, acl}}
    end.

-spec authorize_operation(
    Prototype :: capi_bouncer_context:prototypes(),
    Provider :: provider()
) -> resolution().
authorize_operation(Prototype, {bouncer, Fragments0, WoodyCtx}) ->
    Fragments1 = capi_bouncer_context:build(Prototype, Fragments0, WoodyCtx),
    capi_bouncer:judge(Fragments1, WoodyCtx);
authorize_operation(Context, {legacy, ACL}) ->
    authorize_operation_legacy(Context, ACL).

authorize_operation_legacy(Context, ACL) ->
    % NOTE
    % Operation context prototype MUST be present here at all times.
    {operation, #{id := OperationID} = OperationContext} = lists:keyfind(operation, 1, Context),
    authorize_acl(OperationID, OperationContext, ACL).

authorize_acl(OperationID, OperationContext, ACL) ->
    Access = get_operation_access(OperationID, OperationContext),
    case
        lists:all(
            fun({Scope, Permission}) ->
                lists:member(Permission, capi_acl:match(Scope, ACL))
            end,
            Access
        )
    of
        true ->
            allowed;
        false ->
            forbidden
    end.

get_auth_context(#{auth_context := AuthContext}) ->
    AuthContext.

%%

%% TODO
%% Hardcode for now, should pass it here probably as an argument
-define(DEFAULT_INVOICE_ACCESS_TOKEN_LIFETIME, 259200).
-define(DEFAULT_CUSTOMER_ACCESS_TOKEN_LIFETIME, 259200).

%% TODO
%% This is kinda brittle, how do we ensure this string is correct, besides tests?
-define(AUTH_METHOD_INVOICE_ACCESS_TOKEN, <<"InvoiceAccessToken">>).
-define(AUTH_METHOD_INVTPL_ACCESS_TOKEN, <<"InvoiceTemplateAccessToken">>).
-define(AUTH_METHOD_CUSTOMER_ACCESS_TOKEN, <<"CustomerAccessToken">>).

-spec issue_invoice_access_token(PartyID :: binary(), InvoiceID :: binary(), claims()) ->
    {ok, capi_authorizer_jwt:token()} | {error, _}.
issue_invoice_access_token(PartyID, InvoiceID, Claims) ->
    ACL = [
        {[{invoices, InvoiceID}], read},
        {[{invoices, InvoiceID}, payments], read},
        {[{invoices, InvoiceID}, payments], write},
        {[payment_resources], write}
    ],
    ExpiresAt = lifetime_to_expiration(?DEFAULT_INVOICE_ACCESS_TOKEN_LIFETIME),
    AuthParams = #{
        method => ?AUTH_METHOD_INVOICE_ACCESS_TOKEN,
        expiration => make_auth_expiration(ExpiresAt),
        scope => [
            #{
                party => #{id => PartyID},
                invoice => #{id => InvoiceID}
            }
        ]
    },
    issue_access_token(PartyID, Claims, ACL, AuthParams, ExpiresAt).

-spec issue_invoice_template_access_token(PartyID :: binary(), InvoiceTplID :: binary(), claims()) ->
    {ok, capi_authorizer_jwt:token()} | {error, _}.
issue_invoice_template_access_token(PartyID, InvoiceTplID, Claims) ->
    ACL = [
        {[party, {invoice_templates, InvoiceTplID}], read},
        {[party, {invoice_templates, InvoiceTplID}, invoice_template_invoices], write}
    ],
    AuthParams = #{
        method => ?AUTH_METHOD_INVTPL_ACCESS_TOKEN,
        expiration => make_auth_expiration(unlimited),
        scope => [
            #{
                party => #{id => PartyID},
                invoice_template => #{id => InvoiceTplID}
            }
        ]
    },
    issue_access_token(PartyID, Claims, ACL, AuthParams, unlimited).

-spec issue_customer_access_token(PartyID :: binary(), CustomerID :: binary(), claims()) ->
    {ok, capi_authorizer_jwt:token()} | {error, _}.
issue_customer_access_token(PartyID, CustomerID, Claims) ->
    ACL = [
        {[{customers, CustomerID}], read},
        {[{customers, CustomerID}, bindings], read},
        {[{customers, CustomerID}, bindings], write},
        {[payment_resources], write}
    ],
    ExpiresAt = lifetime_to_expiration(?DEFAULT_CUSTOMER_ACCESS_TOKEN_LIFETIME),
    AuthParams = #{
        method => ?AUTH_METHOD_CUSTOMER_ACCESS_TOKEN,
        expiration => make_auth_expiration(ExpiresAt),
        scope => [
            #{
                party => #{id => PartyID},
                customer => #{id => CustomerID}
            }
        ]
    },
    issue_access_token(PartyID, Claims, ACL, AuthParams, ExpiresAt).

-type acl() :: [{capi_acl:scope(), capi_acl:permission()}].

-spec issue_access_token(
    PartyID :: binary(),
    claims(),
    acl(),
    bouncer_context_helpers:auth_params(),
    capi_authorizer_jwt:expiration()
) -> {ok, capi_authorizer_jwt:token()} | {error, _}.
issue_access_token(PartyID, BaseClaims, ACL, BaseAuthParams, ExpiresAt) ->
    TokenID = capi_authorizer_jwt:unique_id(),
    AuthParams = BaseAuthParams#{token => #{id => TokenID}},
    ContextFragment = bouncer_context_helpers:make_auth_fragment(AuthParams),
    Claims1 = capi_authorizer_jwt:set_token_id(TokenID, BaseClaims),
    Claims2 = capi_authorizer_jwt:set_subject_id(PartyID, Claims1),
    Claims3 = capi_authorizer_jwt:set_expires_at(ExpiresAt, Claims2),
    Claims4 = capi_authorizer_jwt:set_acl(capi_acl:from_list(ACL), Claims3),
    Claims5 = capi_bouncer:set_claim(ContextFragment, Claims4),
    capi_authorizer_jwt:issue(Claims5).

lifetime_to_expiration(Lt) ->
    genlib_time:unow() + Lt.

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.

-spec get_subject_id(context()) -> binary().
get_subject_id({auth_data, AuthData}) ->
    capi_token_keeper:get_subject_id(AuthData);
get_subject_id({legacy, {Claims, _}}) ->
    capi_authorizer_jwt:get_subject_id(Claims).

-spec get_subject_email(context()) -> binary().
get_subject_email({auth_data, AuthData}) ->
    capi_token_keeper:get_subject_email(AuthData);
get_subject_email({legacy, {Claims, _}}) ->
    capi_authorizer_jwt:get_subject_email(Claims).

%%

-spec get_operation_access(swag_server:operation_id(), capi_bouncer_context:prototype_operation()) ->
    [{capi_acl:scope(), capi_acl:permission()}].
get_operation_access('CreateInvoice', _) ->
    [{[invoices], write}];
get_operation_access('GetInvoiceByID', #{invoice := ID}) ->
    [{[{invoices, ID}], read}];
get_operation_access('GetInvoiceEvents', #{invoice := ID}) ->
    [{[{invoices, ID}], read}];
get_operation_access('GetInvoicePaymentMethods', #{invoice := ID}) ->
    [{[{invoices, ID}], read}];
get_operation_access('FulfillInvoice', #{invoice := ID}) ->
    [{[{invoices, ID}], write}];
get_operation_access('RescindInvoice', #{invoice := ID}) ->
    [{[{invoices, ID}], write}];
get_operation_access('CreateInvoiceAccessToken', #{invoice := ID}) ->
    [{[{invoices, ID}], write}];
get_operation_access('CreatePayment', #{invoice := ID}) ->
    [{[{invoices, ID}, payments], write}];
get_operation_access('GetPayments', #{invoice := ID}) ->
    [{[{invoices, ID}, payments], read}];
get_operation_access('GetPaymentByID', #{invoice := ID1, payment := ID2}) ->
    [{[{invoices, ID1}, {payments, ID2}], read}];
get_operation_access('CancelPayment', #{invoice := ID1, payment := ID2}) ->
    [{[{invoices, ID1}, {payments, ID2}], write}];
get_operation_access('CapturePayment', #{invoice := ID1, payment := ID2}) ->
    [{[{invoices, ID1}, {payments, ID2}], write}];
get_operation_access('CreateRefund', _) ->
    [{[invoices, payments], write}];
get_operation_access('GetRefunds', _) ->
    [{[invoices, payments], read}];
get_operation_access('GetRefundByID', _) ->
    [{[invoices, payments], read}];
get_operation_access('SearchInvoices', _) ->
    [{[invoices], read}];
get_operation_access('SearchPayments', _) ->
    [{[invoices, payments], read}];
get_operation_access('SearchPayouts', _) ->
    [{[party], read}];
get_operation_access('CreatePaymentResource', _) ->
    [{[payment_resources], write}];
get_operation_access('GetPaymentConversionStats', _) ->
    [{[party], read}];
get_operation_access('GetPaymentRevenueStats', _) ->
    [{[party], read}];
get_operation_access('GetPaymentGeoStats', _) ->
    [{[party], read}];
get_operation_access('GetPaymentRateStats', _) ->
    [{[party], read}];
get_operation_access('GetPaymentMethodStats', _) ->
    [{[party], read}];
get_operation_access('GetMyParty', _) ->
    [{[party], read}];
get_operation_access('ActivateShop', _) ->
    [{[party], write}];
get_operation_access('SuspendShop', _) ->
    [{[party], write}];
get_operation_access('SuspendMyParty', _) ->
    [{[party], write}];
get_operation_access('ActivateMyParty', _) ->
    [{[party], write}];
get_operation_access('CreateClaim', _) ->
    [{[party], write}];
get_operation_access('GetClaims', _) ->
    [{[party], read}];
get_operation_access('GetClaimByID', _) ->
    [{[party], read}];
get_operation_access('GetClaimsByStatus', _) ->
    [{[party], read}];
get_operation_access('RevokeClaimByID', _) ->
    [{[party], write}];
get_operation_access('GetAccountByID', _) ->
    [{[party], read}];
get_operation_access('GetShopByID', _) ->
    [{[party], read}];
get_operation_access('GetShops', _) ->
    [{[party], read}];
get_operation_access('GetPayoutTools', _) ->
    [{[party], read}];
get_operation_access('GetPayoutToolByID', _) ->
    [{[party], read}];
get_operation_access('GetContracts', _) ->
    [{[party], read}];
get_operation_access('GetContractByID', _) ->
    [{[party], read}];
get_operation_access('GetContractAdjustments', _) ->
    [{[party], read}];
get_operation_access('GetContractAdjustmentByID', _) ->
    [{[party], read}];
get_operation_access('GetReports', _) ->
    [{[party], read}];
get_operation_access('DownloadFile', _) ->
    [{[party], read}];
get_operation_access('GetWebhooks', _) ->
    [{[party], read}];
get_operation_access('GetWebhookByID', _) ->
    [{[party], read}];
get_operation_access('CreateWebhook', _) ->
    [{[party], write}];
get_operation_access('DeleteWebhookByID', _) ->
    [{[party], write}];
get_operation_access('CreateInvoiceTemplate', _) ->
    [{[party], write}];
get_operation_access('GetInvoiceTemplateByID', #{invoice_template := ID}) ->
    [{[party, {invoice_templates, ID}], read}];
get_operation_access('UpdateInvoiceTemplate', #{invoice_template := ID}) ->
    [{[party, {invoice_templates, ID}], write}];
get_operation_access('DeleteInvoiceTemplate', #{invoice_template := ID}) ->
    [{[party, {invoice_templates, ID}], write}];
get_operation_access('CreateInvoiceWithTemplate', #{invoice_template := ID}) ->
    [{[party, {invoice_templates, ID}, invoice_template_invoices], write}];
get_operation_access('GetInvoicePaymentMethodsByTemplateID', #{invoice_template := ID}) ->
    [{[party, {invoice_templates, ID}], read}];
get_operation_access('CreateCustomer', _) ->
    [{[customers], write}];
get_operation_access('GetCustomerById', #{customer := ID}) ->
    [{[{customers, ID}], read}];
get_operation_access('DeleteCustomer', #{customer := ID}) ->
    [{[{customers, ID}], write}];
get_operation_access('CreateCustomerAccessToken', #{customer := ID}) ->
    [{[{customers, ID}], write}];
get_operation_access('CreateBinding', #{customer := ID}) ->
    [{[{customers, ID}, bindings], write}];
get_operation_access('GetBindings', #{customer := ID}) ->
    [{[{customers, ID}, bindings], read}];
get_operation_access('GetBinding', #{customer := ID1, binding := ID2}) ->
    [{[{customers, ID1}, {bindings, ID2}], read}];
get_operation_access('GetCustomerEvents', #{customer := ID}) ->
    [{[{customers, ID}], read}];
get_operation_access('GetCategories', _) ->
    [];
get_operation_access('GetCategoryByRef', _) ->
    [];
get_operation_access('GetScheduleByRef', _) ->
    [];
get_operation_access('GetPaymentInstitutions', _) ->
    [];
get_operation_access('GetPaymentInstitutionByRef', _) ->
    [];
get_operation_access('GetPaymentInstitutionPaymentTerms', _) ->
    [{[party], read}];
get_operation_access('GetPaymentInstitutionPayoutMethods', _) ->
    [{[party], read}];
get_operation_access('GetPaymentInstitutionPayoutSchedules', _) ->
    [{[party], read}];
get_operation_access('GetLocationsNames', _) ->
    [].

-spec get_resource_hierarchy() -> #{atom() => map()}.
get_resource_hierarchy() ->
    #{
        party => #{invoice_templates => #{invoice_template_invoices => #{}}},
        customers => #{bindings => #{}},
        invoices => #{payments => #{}},
        payment_resources => #{},
        payouts => #{}
    }.
