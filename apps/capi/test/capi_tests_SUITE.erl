-module(capi_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("capi_dummy_data.hrl").
-include_lib("capi_bouncer_data.hrl").

-include_lib("damsel/include/dmsl_payment_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_processing_errors_thrift.hrl").
-include_lib("damsel/include/dmsl_accounter_thrift.hrl").
-include_lib("damsel/include/dmsl_cds_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").
-include_lib("damsel/include/dmsl_webhooker_thrift.hrl").
-include_lib("damsel/include/dmsl_merch_stat_thrift.hrl").
-include_lib("reporter_proto/include/reporter_reports_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_provider_thrift.hrl").
-include_lib("damsel/include/dmsl_payout_processing_thrift.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([init/1]).

-export([
    woody_unexpected_test/1,
    woody_unavailable_test/1,
    woody_retry_test/1,
    woody_unknown_test/1,

    authorization_positive_lifetime_ok_test/1,
    authorization_unlimited_lifetime_ok_test/1,
    authorization_far_future_deadline_ok_test/1,
    authorization_permission_ok_test/1,
    authorization_negative_lifetime_error_test/1,
    authorization_bad_deadline_error_test/1,
    authorization_error_no_header_test/1,
    authorization_error_no_permission_test/1,
    authorization_bad_token_error_test/1,

    create_invoice_ok_test/1,
    get_invoice_ok_test/1,
    get_invoice_events_ok_test/1,
    get_invoice_payment_methods_ok_test/1,
    create_invoice_access_token_ok_test/1,
    rescind_invoice_ok_test/1,
    fulfill_invoice_ok_test/1,

    create_invoice_with_tpl_ok_test/1,
    create_invoice_template_ok_test/1,
    get_invoice_template_ok_test/1,
    update_invoice_template_ok_test/1,
    delete_invoice_template_ok_test/1,
    get_invoice_payment_methods_by_tpl_id_ok_test/1,

    get_account_by_id_ok_test/1,

    create_payment_ok_test/1,
    create_payment_expired_test/1,
    create_payment_with_encrypt_token_ok_test/1,
    get_payments_ok_test/1,
    get_payment_by_id_ok_test/1,
    get_payment_by_id_error_test/1,
    create_refund/1,
    create_refund_idemp_ok_test/1,
    create_partial_refund/1,
    create_partial_refund_without_currency/1,
    get_refund_by_id/1,
    get_refunds/1,
    cancel_payment_ok_test/1,
    capture_payment_ok_test/1,

    get_my_party_ok_test/1,
    suspend_my_party_ok_test/1,
    activate_my_party_ok_test/1,

    get_shop_by_id_ok_test/1,
    get_shops_ok_test/1,
    activate_shop_ok_test/1,
    suspend_shop_ok_test/1,

    get_claim_by_id_ok_test/1,
    get_claims_ok_test/1,
    revoke_claim_ok_test/1,
    create_claim_ok_test/1,
    update_claim_by_id_test/1,

    get_contract_by_id_ok_test/1,
    get_contracts_ok_test/1,
    get_contract_adjustments_ok_test/1,
    get_contract_adjustment_by_id_ok_test/1,

    get_payout_tools_ok_test/1,
    get_payout_tool_by_id/1,

    create_webhook_ok_test/1,
    get_webhooks/1,
    get_webhook_by_id/1,
    delete_webhook_by_id/1,

    get_locations_names_ok_test/1,

    search_invoices_ok_test/1,
    search_payments_ok_test/1,
    search_payouts_ok_test/1,

    get_payment_conversion_stats_ok_test/1,
    get_payment_revenue_stats_ok_test/1,
    get_payment_geo_stats_ok_test/1,
    get_payment_rate_stats_ok_test/1,
    get_payment_method_stats_ok_test/1,

    get_reports_ok_test/1,
    download_report_file_ok_test/1,
    download_report_file_not_found_test/1,

    get_categories_ok_test/1,
    get_category_by_ref_ok_test/1,
    get_schedule_by_ref_ok_test/1,
    get_payment_institutions/1,
    get_payment_institution_by_ref/1,
    get_payment_institution_payment_terms/1,
    get_payment_institution_payout_schedules/1,
    get_payment_institution_payout_methods/1,

    create_customer_ok_test/1,
    get_customer_ok_test/1,
    create_customer_access_token_ok_test/1,
    create_binding_ok_test/1,
    create_binding_expired_test/1,
    get_bindings_ok_test/1,
    get_binding_ok_test/1,
    get_customer_events_ok_test/1,
    delete_customer_ok_test/1,

    session_token_context_matches/1,
    invoice_access_token_context_matches/1,
    invoice_template_access_token_context_matches/1,
    customer_access_token_context_matches/1,

    check_support_decrypt_v1_test/1,
    check_support_decrypt_v2_test/1
]).

-define(CAPI_IP, "::").
-define(CAPI_PORT, 8080).
-define(CAPI_HOST_NAME, "localhost").
-define(CAPI_URL, ?CAPI_HOST_NAME ++ ":" ++ integer_to_list(?CAPI_PORT)).

-define(SESSION_KEY_METADATA, #{
    auth_method => user_session_token,
    user_realm => ?TEST_USER_REALM
}).

-define(META_NS_USER_SESSION, <<"com.rbkmoney.keycloak">>).
-define(META_NS_API_KEY, <<"com.rbkmoney.apikeymgmt">>).

-define(badresp(Code), {error, {invalid_response_code, Code}}).

-type test_case_name() :: atom().
-type config() :: [{atom(), any()}].
-type group_name() :: atom().

-behaviour(supervisor).

-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-spec all() -> [{group, test_case_name()}].
all() ->
    [
        {group, woody_errors},
        {group, operations_by_base_api_token},
        {group, operations_by_legacy_invoice_access_token},
        {group, operations_by_legacy_invoice_template_access_token},
        {group, operations_by_legacy_customer_access_token},
        {group, authorization},
        {group, authorization_context},
        {group, payment_tool_token_support}
    ].

invoice_access_token_tests() ->
    [
        get_invoice_ok_test,
        get_invoice_events_ok_test,
        get_invoice_payment_methods_ok_test,
        create_payment_ok_test,
        create_payment_expired_test,
        create_payment_with_encrypt_token_ok_test,
        get_payment_by_id_ok_test,
        get_payment_by_id_error_test
    ].

customer_access_token_tests() ->
    [
        get_customer_ok_test,
        create_binding_ok_test,
        create_binding_expired_test,
        get_binding_ok_test,
        get_customer_events_ok_test
    ].

-spec test() -> _.

-spec groups() -> [{group_name(), list(), [test_case_name()]}].

groups() ->
    [
        {woody_errors, [], [
            woody_unexpected_test,
            woody_unavailable_test,
            woody_retry_test,
            woody_unknown_test
        ]},
        {operations_by_base_api_token, [], [
            create_invoice_ok_test,
            create_invoice_access_token_ok_test,
            get_invoice_ok_test,
            create_payment_ok_test,
            get_payments_ok_test,
            get_payment_by_id_ok_test,
            capture_payment_ok_test,
            cancel_payment_ok_test,
            rescind_invoice_ok_test,
            fulfill_invoice_ok_test,
            create_refund,
            create_refund_idemp_ok_test,
            create_partial_refund,
            create_partial_refund_without_currency,
            get_refund_by_id,
            get_refunds,
            create_customer_ok_test,
            create_customer_access_token_ok_test,
            create_binding_ok_test,
            get_binding_ok_test,
            get_bindings_ok_test,
            delete_customer_ok_test,
            create_invoice_template_ok_test,
            update_invoice_template_ok_test,
            delete_invoice_template_ok_test,
            get_account_by_id_ok_test,
            get_my_party_ok_test,
            suspend_my_party_ok_test,
            activate_my_party_ok_test,
            get_shop_by_id_ok_test,
            get_shops_ok_test,
            activate_shop_ok_test,
            suspend_shop_ok_test,
            get_claim_by_id_ok_test,
            get_claims_ok_test,
            revoke_claim_ok_test,
            create_claim_ok_test,
            update_claim_by_id_test,
            get_contract_by_id_ok_test,
            get_contracts_ok_test,
            get_contract_adjustments_ok_test,
            get_contract_adjustment_by_id_ok_test,
            get_payout_tools_ok_test,
            get_payout_tool_by_id,
            create_webhook_ok_test,
            get_webhooks,
            get_webhook_by_id,
            delete_webhook_by_id,
            get_locations_names_ok_test,
            search_invoices_ok_test,
            search_payments_ok_test,
            search_payouts_ok_test,
            get_payment_conversion_stats_ok_test,
            get_payment_revenue_stats_ok_test,
            get_payment_geo_stats_ok_test,
            get_payment_rate_stats_ok_test,
            get_payment_method_stats_ok_test,
            get_reports_ok_test,
            download_report_file_ok_test,
            download_report_file_not_found_test,
            get_categories_ok_test,
            get_category_by_ref_ok_test,
            get_schedule_by_ref_ok_test,
            get_payment_institutions,
            get_payment_institution_by_ref,
            get_payment_institution_payment_terms,
            get_payment_institution_payout_schedules,
            get_payment_institution_payout_methods
        ]},
        {operations_by_legacy_invoice_access_token, [], invoice_access_token_tests()},
        {operations_by_legacy_invoice_template_access_token, [], [
            create_invoice_with_tpl_ok_test,
            get_invoice_template_ok_test,
            get_invoice_payment_methods_by_tpl_id_ok_test
        ]},
        {operations_by_legacy_customer_access_token, [], customer_access_token_tests()},
        {authorization, [], [
            authorization_positive_lifetime_ok_test,
            authorization_unlimited_lifetime_ok_test,
            authorization_far_future_deadline_ok_test,
            authorization_permission_ok_test,
            authorization_negative_lifetime_error_test,
            authorization_bad_deadline_error_test,
            authorization_error_no_header_test,
            authorization_error_no_permission_test,
            authorization_bad_token_error_test
        ]},
        {authorization_context, [], [
            session_token_context_matches,
            invoice_access_token_context_matches,
            invoice_template_access_token_context_matches,
            customer_access_token_context_matches
        ]},
        {payment_tool_token_support, [], [
            check_support_decrypt_v1_test,
            check_support_decrypt_v2_test
        ]}
    ].

%%
%% starting/stopping
%%
-spec init_per_suite(config()) -> config().
init_per_suite(Config) ->
    SupPid = start_mocked_service_sup(),
    Apps = capi_ct_helper:start_app(woody) ++ start_dmt_client(SupPid) ++ mock_bouncer_client(SupPid),
    [{suite_apps, Apps}, {suite_test_sup, SupPid} | Config].

start_dmt_client(SupPid) ->
    ServiceURLs = mock_services(
        [
            {
                'Repository',
                {dmsl_domain_config_thrift, 'Repository'},
                fun
                    ('Checkout', _) -> {ok, ?SNAPSHOT};
                    ('PullRange', _) -> {ok, #{}}
                end
            }
        ],
        SupPid
    ),
    capi_ct_helper:start_app(dmt_client, [{max_cache_size, #{}}, {service_urls, ServiceURLs}]).

-spec end_per_suite(config()) -> _.
end_per_suite(C) ->
    _ = stop_mocked_service_sup(?config(suite_test_sup, C)),
    _ = [application:stop(App) || App <- lists:reverse(proplists:get_value(suite_apps, C))],
    ok.

-spec init_per_group(group_name(), config()) -> config().
init_per_group(operations_by_legacy_invoice_access_token, Config) ->
    Apps = start_capi(#{capi => make_key_opts("keys/local/capi.pem", #{}, Config)}, Config),
    ACL = [
        {[{invoices, ?STRING}], read},
        {[{invoices, ?STRING}, payments], read},
        {[{invoices, ?STRING}, payments], write},
        {[payment_resources], write}
    ],
    {ok, Token} = issue_token(capi, ?STRING, ACL, unlimited),
    [{context, get_context(Token)}, {group_apps, Apps} | Config];
init_per_group(operations_by_legacy_invoice_template_access_token, Config) ->
    Apps = start_capi(#{capi => make_key_opts("keys/local/capi.pem", #{}, Config)}, Config),
    ACL = [
        {[party, {invoice_templates, ?STRING}], read},
        {[party, {invoice_templates, ?STRING}, invoice_template_invoices], write}
    ],
    {ok, Token} = issue_token(capi, ?STRING, ACL, unlimited),
    [{context, get_context(Token)}, {group_apps, Apps} | Config];
init_per_group(operations_by_legacy_customer_access_token, Config) ->
    Apps = start_capi(#{capi => make_key_opts("keys/local/capi.pem", #{}, Config)}, Config),
    ACL = [
        {[{customers, ?STRING}], read},
        {[{customers, ?STRING}, bindings], read},
        {[{customers, ?STRING}, bindings], write},
        {[payment_resources], write}
    ],
    {ok, Token} = issue_token(capi, ?STRING, ACL, unlimited),
    [{context, get_context(Token)}, {group_apps, Apps} | Config];
init_per_group(operations_by_base_api_token, Config) ->
    Apps1 = start_capi(
        #{capi => make_key_opts("keys/local/capi.pem", ?SESSION_KEY_METADATA, Config)},
        Config
    ),
    ACL = [
        {[invoices], write},
        {[invoices], read},
        {[party], write},
        {[party], read},
        {[invoices, payments], write},
        {[invoices, payments], read},
        {[customers], write}
    ],
    {ok, Token} = issue_token(capi, ?STRING, ACL, unlimited),
    Context = get_context(Token),
    [{context, Context}, {group_apps, Apps1} | Config];
init_per_group(GroupName, Config) when GroupName == woody_errors; GroupName == authorization ->
    SupPid = start_mocked_service_sup(),
    Apps1 = mock_bouncer_arbiter(judge_always_allowed(), SupPid),
    Apps2 = start_capi(
        #{
            capi => make_key_opts("keys/local/capi.pem", ?SESSION_KEY_METADATA, Config),
            capi_wo_bouncer => make_key_opts("keys/local/capi_wo_bouncer.pem", #{}, Config)
        },
        Config
    ),
    {ok, Token} = issue_token(capi, ?STRING, [], unlimited),
    Context = get_context(Token),
    [{context, Context}, {group_apps, Apps1 ++ Apps2}, {group_test_sup, SupPid} | Config];
init_per_group(GroupName, Config) when GroupName == authorization_context; GroupName == payment_tool_token_support ->
    Apps = start_capi(#{capi => make_key_opts("keys/local/capi.pem", ?SESSION_KEY_METADATA, Config)}, Config),
    [{group_apps, Apps} | Config].

make_key_opts(Source, Metadata, Config) ->
    #{
        source => {pem_file, get_keysource(Source, Config)},
        metadata => Metadata
    }.

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_Group, C) ->
    _ = capi_utils:maybe(?config(group_test_sup, C), fun stop_mocked_service_sup/1),
    [application:stop(App) || App <- lists:reverse(proplists:get_value(group_apps, C, []))].

-spec init_per_testcase(test_case_name(), config()) -> config().
init_per_testcase(_Name, C) ->
    [{test_sup, start_mocked_service_sup()} | C].

-spec end_per_testcase(test_case_name(), config()) -> _.
end_per_testcase(_Name, C) ->
    stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests

-spec woody_unexpected_test(config()) -> _.
woody_unexpected_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> {ok, "spanish inquisition"} end}
        ],
        Config
    ),
    ?badresp(500) = capi_client_parties:get_my_party(?config(context, Config)).

-spec woody_unavailable_test(config()) -> _.
woody_unavailable_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config, #{
        party_management => <<"http://spanish.inquision/v1/partymgmt">>
    }),
    ?badresp(503) = capi_client_parties:get_my_party(?config(context, Config)).

-spec woody_retry_test(config()) -> _.
woody_retry_test(Config) ->
    _ = mock_woody_client(
        [{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}],
        Config,
        #{
            party_management => <<"http://spanish.inquision/v1/partymgmt">>
        },
        [
            {service_retries, #{
                party_management => #{
                    'Get' => {linear, 30, 1000},
                    '_' => finish
                }
            }},
            {service_deadlines, #{
                party_management => 5000
            }}
        ]
    ),
    {Time, ?badresp(503)} = timer:tc(capi_client_parties, get_my_party, [?config(context, Config)]),
    _ = ?assert(Time > 4000000),
    _ = ?assert(Time < 6000000).

-spec woody_unknown_test(config()) -> _.
woody_unknown_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> timer:sleep(60000) end}
        ],
        Config
    ),
    ?badresp(504) = capi_client_parties:get_my_party(?config(context, Config)).

-spec authorization_positive_lifetime_ok_test(config()) -> _.
authorization_positive_lifetime_ok_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    {ok, Token} = issue_token(capi, ?STRING, [], {lifetime, 10}),
    {ok, _} = capi_client_categories:get_categories(get_context(Token)).

-spec authorization_unlimited_lifetime_ok_test(config()) -> _.
authorization_unlimited_lifetime_ok_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    {ok, Token} = issue_token(capi, ?STRING, [], unlimited),
    {ok, _} = capi_client_categories:get_categories(get_context(Token)).

-spec authorization_far_future_deadline_ok_test(config()) -> _.
authorization_far_future_deadline_ok_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    % 01/01/2100 @ 12:00am (UTC)
    {ok, Token} = issue_token(capi, ?STRING, [], {deadline, 4102444800}),
    {ok, _} = capi_client_categories:get_categories(get_context(Token)).

-spec authorization_permission_ok_test(config()) -> _.
authorization_permission_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> {ok, ?PARTY} end}
        ],
        Config
    ),
    {ok, Token} = issue_token(capi, ?STRING, [{[party], read}], unlimited),
    {ok, _} = capi_client_parties:get_my_party(get_context(Token)).

-spec authorization_negative_lifetime_error_test(config()) -> _.
authorization_negative_lifetime_error_test(_Config) ->
    ok.

% {ok, Token} = issue_token([], {lifetime, -10}),
% ?badresp(401) = capi_client_categories:get_categories(get_context(Token)).

-spec authorization_bad_deadline_error_test(config()) -> _.
authorization_bad_deadline_error_test(_Config) ->
    ok.

% {ok, Token} = issue_token([], {deadline, -10}),
% ?badresp(401) = capi_client_categories:get_categories(get_context(Token)).

-spec authorization_error_no_header_test(config()) -> _.
authorization_error_no_header_test(_Config) ->
    Token = <<>>,
    ?badresp(401) = capi_client_categories:get_categories(get_context(Token)).

-spec authorization_error_no_permission_test(config()) -> _.
authorization_error_no_permission_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:not_found_handler/2}], Config),
    {ok, Token} = issue_token(capi_wo_bouncer, ?STRING, [], {lifetime, 10}),
    ?badresp(401) = capi_client_parties:get_my_party(get_context(Token)).

-spec authorization_bad_token_error_test(config()) -> _.
authorization_bad_token_error_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:not_found_handler/2}], Config),
    {ok, Token} = issue_dummy_token([{[party], read}], Config),
    ?badresp(401) = capi_client_parties:get_my_party(get_context(Token)).

-spec session_token_context_matches(config()) -> _.
session_token_context_matches(Config) ->
    UserID = <<"session_token_context_matches">>,
    Timestamp = <<"2100-01-01T12:00:00Z">>,
    Deadline = {deadline, genlib_rfc3339:parse(Timestamp, second)},
    {ok, SessionToken} = issue_token(capi, UserID, [], Deadline),
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> {ok, ?PARTY} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                env = #bctx_v1_Environment{
                    now = <<_/binary>>,
                    deployment = #bctx_v1_Deployment{id = ?TEST_CAPI_DEPLOYMENT}
                },
                auth = #bctx_v1_Auth{
                    method = <<"SessionToken">>,
                    expiration = Timestamp,
                    token = #bctx_v1_Token{id = <<_/binary>>}
                },
                user = #bctx_v1_User{
                    id = UserID,
                    realm = ?CTX_ENTITY(?TEST_USER_REALM),
                    orgs = [#bctx_v1_Organization{id = ?STRING, owner = ?CTX_ENTITY(UserID)}]
                }
            }
        ),
        Config
    ),
    {ok, _} = capi_client_parties:get_my_party(get_context(SessionToken)).

-spec invoice_access_token_context_matches(config()) -> _.
invoice_access_token_context_matches(Config) ->
    {ok, AccessToken} = capi_auth:issue_invoice_access_token(?STRING, ?STRING, #{}),
    _ = mock_woody_client(
        [
            {token_keeper, fun('GetByToken', {Token, _}) ->
                capi_ct_helper_tk:mock_handler(
                    Token,
                    <<"com.rbkmoney.capi">>,
                    [
                        {auth, [
                            {method, <<"InvoiceAccessToken">>},
                            expiration,
                            token,
                            {scope, [[{party, ?STRING}, {invoice, ?STRING}]]}
                        ]}
                    ],
                    [api_key_meta]
                )
            end},
            {invoicing, fun('Get', _) -> {ok, ?PAYPROC_INVOICE} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                env = #bctx_v1_Environment{},
                auth = #bctx_v1_Auth{
                    method = <<"InvoiceAccessToken">>,
                    expiration = <<_/binary>>,
                    token = #bctx_v1_Token{id = <<_/binary>>},
                    scope = [
                        #bctx_v1_AuthScope{
                            party = ?CTX_ENTITY(?STRING),
                            invoice = ?CTX_ENTITY(?STRING)
                        }
                    ]
                },
                user = undefined
            }
        ),
        Config
    ),
    {ok, _} = capi_client_invoices:get_invoice_by_id(get_context(AccessToken), ?STRING).

-spec invoice_template_access_token_context_matches(config()) -> _.
invoice_template_access_token_context_matches(Config) ->
    {ok, AccessToken} = capi_auth:issue_invoice_template_access_token(?STRING, ?STRING, #{}),
    _ = mock_woody_client(
        [
            {token_keeper, fun('GetByToken', {Token, _}) ->
                capi_ct_helper_tk:mock_handler(
                    Token,
                    <<"com.rbkmoney.capi">>,
                    [
                        {auth, [
                            {method, <<"InvoiceTemplateAccessToken">>},
                            expiration,
                            token,
                            {scope, [[{party, ?STRING}, {invoice_template, ?STRING}]]}
                        ]}
                    ],
                    [api_key_meta]
                )
            end},
            {invoice_templating, fun('Get', _) -> {ok, ?INVOICE_TPL} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                env = #bctx_v1_Environment{},
                auth = #bctx_v1_Auth{
                    method = <<"InvoiceTemplateAccessToken">>,
                    expiration = undefined,
                    token = #bctx_v1_Token{id = <<_/binary>>},
                    scope = [
                        #bctx_v1_AuthScope{
                            party = ?CTX_ENTITY(?STRING),
                            invoice_template = ?CTX_ENTITY(?STRING)
                        }
                    ]
                },
                user = undefined
            }
        ),
        Config
    ),
    {ok, _} = capi_client_invoice_templates:get_template_by_id(get_context(AccessToken), ?STRING).

-spec customer_access_token_context_matches(config()) -> _.
customer_access_token_context_matches(Config) ->
    {ok, AccessToken} = capi_auth:issue_customer_access_token(?STRING, ?STRING, #{}),
    _ = mock_woody_client(
        [
            {token_keeper, fun('GetByToken', {Token, _}) ->
                capi_ct_helper_tk:mock_handler(
                    Token,
                    <<"com.rbkmoney.capi">>,
                    [
                        {auth, [
                            {method, <<"CustomerAccessToken">>},
                            expiration,
                            token,
                            {scope, [[{party, ?STRING}, {customer, ?STRING}]]}
                        ]}
                    ],
                    [api_key_meta]
                )
            end},
            {customer_management, fun('Get', _) -> {ok, ?CUSTOMER} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                env = #bctx_v1_Environment{},
                auth = #bctx_v1_Auth{
                    method = <<"CustomerAccessToken">>,
                    expiration = <<_/binary>>,
                    token = #bctx_v1_Token{id = <<_/binary>>},
                    scope = [
                        #bctx_v1_AuthScope{
                            party = ?CTX_ENTITY(?STRING),
                            customer = ?CTX_ENTITY(?STRING)
                        }
                    ]
                },
                user = undefined
            }
        ),
        Config
    ),
    {ok, _} = capi_client_customers:get_customer_by_id(get_context(AccessToken), ?STRING).

-spec create_invoice_ok_test(config()) -> _.
create_invoice_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"key">>)} end},
            {invoicing, fun('Create', {_, #payproc_InvoiceParams{id = <<"key">>}}) -> {ok, ?PAYPROC_INVOICE} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"CreateInvoice">>, ?STRING, ?STRING, Config),
    Req = #{
        <<"shopID">> => ?STRING,
        <<"amount">> => ?INTEGER,
        <<"currency">> => ?RUB,
        <<"metadata">> => #{<<"invoice_dummy_metadata">> => <<"test_value">>},
        <<"dueDate">> => ?TIMESTAMP,
        <<"product">> => <<"test_product">>,
        <<"description">> => <<"test_invoice_description">>
    },
    {ok, _} = capi_client_invoices:create_invoice(?config(context, Config), Req).

-spec create_invoice_with_tpl_ok_test(config()) -> _.
create_invoice_with_tpl_ok_test(Config) ->
    _ = mock_woody_client(
        [
            %% @NOTE This is weird (is there a bouncer mock missing?)
            {token_keeper, fun capi_ct_helper_tk:not_found_handler/2},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"key">>)} end},
            {invoice_templating, fun('Get', {_, ?STRING}) -> {ok, ?INVOICE_TPL} end},
            {invoicing, fun('CreateWithTemplate', {_, #payproc_InvoiceWithTemplateParams{id = <<"key">>}}) ->
                {ok, ?PAYPROC_INVOICE}
            end}
        ],
        Config
    ),
    Req = #{
        <<"amount">> => ?INTEGER,
        <<"currency">> => ?RUB,
        <<"metadata">> => #{<<"invoice_dummy_metadata">> => <<"test_value">>}
    },
    {ok, _} = capi_client_invoice_templates:create_invoice(?config(context, Config), ?STRING, Req).

-spec get_invoice_ok_test(config()) -> _.
get_invoice_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', _) -> {ok, ?PAYPROC_INVOICE} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"GetInvoiceByID">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_invoices:get_invoice_by_id(?config(context, Config), ?STRING).

-spec get_invoice_events_ok_test(config()) -> _.
get_invoice_events_ok_test(Config) ->
    Inc = fun
        (X) when is_integer(X) -> X + 1;
        (_) -> 1
    end,
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) ->
                    {ok, ?PAYPROC_INVOICE};
                ('GetEvents', {_, _, #payproc_EventRange{'after' = ID, limit = N}}) ->
                    {ok,
                        lists:sublist(
                            [
                                ?INVOICE_EVENT(1),
                                ?INVOICE_EVENT(2),
                                ?INVOICE_EVENT_PRIVATE(3),
                                ?INVOICE_EVENT(4),
                                ?INVOICE_EVENT_PRIVATE(5),
                                ?INVOICE_EVENT_PRIVATE(6),
                                ?INVOICE_EVENT(7)
                            ],
                            Inc(ID),
                            N
                        )}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"GetInvoiceEvents">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, [#{<<"id">> := 1}, #{<<"id">> := 2}, #{<<"id">> := 4}]} =
        capi_client_invoices:get_invoice_events(?config(context, Config), ?STRING, 3),
    {ok, [#{<<"id">> := 4}, #{<<"id">> := 7}]} =
        capi_client_invoices:get_invoice_events(?config(context, Config), ?STRING, 2, 3).

-spec get_invoice_payment_methods_ok_test(config()) -> _.
get_invoice_payment_methods_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetRevision', _) -> {ok, ?INTEGER} end},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE};
                ('ComputeTerms', {_, ?STRING, _}) -> {ok, ?TERM_SET}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"GetInvoicePaymentMethods">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_invoices:get_invoice_payment_methods(?config(context, Config), ?STRING).

-spec create_invoice_access_token_ok_test(config()) -> _.
create_invoice_access_token_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', _) -> {ok, ?PAYPROC_INVOICE} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"CreateInvoiceAccessToken">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_invoices:create_invoice_access_token(?config(context, Config), ?STRING).

-spec rescind_invoice_ok_test(config()) -> _.
rescind_invoice_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE};
                ('Rescind', {_, ?STRING, ?STRING}) -> {ok, ok}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"RescindInvoice">>, ?STRING, ?STRING, ?STRING, Config),
    ok = capi_client_invoices:rescind_invoice(?config(context, Config), ?STRING, ?STRING).

-spec fulfill_invoice_ok_test(config()) -> _.
fulfill_invoice_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE};
                ('Fulfill', {_, ?STRING, ?STRING}) -> {ok, ok}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"FulfillInvoice">>, ?STRING, ?STRING, ?STRING, Config),
    ok = capi_client_invoices:fulfill_invoice(?config(context, Config), ?STRING, ?STRING).

-spec create_invoice_template_ok_test(config()) -> _.
create_invoice_template_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoice_templating, fun('Create', _) -> {ok, ?INVOICE_TPL} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"CreateInvoiceTemplate">>, ?STRING, ?STRING, Config),
    Req = #{
        <<"shopID">> => ?STRING,
        <<"lifetime">> => get_lifetime(),
        <<"cost">> => #{
            <<"invoiceTemplateCostType">> => <<"InvoiceTemplateCostFixed">>,
            <<"currency">> => ?RUB,
            <<"amount">> => ?INTEGER
        },
        <<"product">> => <<"test_invoice_template_product">>,
        <<"description">> => <<"test_invoice_template_description">>,
        <<"metadata">> => #{<<"invoice_template_dummy_metadata">> => <<"test_value">>}
    },
    {ok, _} = capi_client_invoice_templates:create(?config(context, Config), Req).

-spec get_invoice_template_ok_test(config()) -> _.
get_invoice_template_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoice_templating, fun('Get', _) -> {ok, ?INVOICE_TPL} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_tpl_op_ctx(<<"GetInvoiceTemplateByID">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_invoice_templates:get_template_by_id(?config(context, Config), ?STRING).

-spec update_invoice_template_ok_test(config()) -> _.
update_invoice_template_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoice_templating, fun
                ('Get', {_, ?STRING}) -> {ok, ?INVOICE_TPL};
                ('Update', {_, ?STRING, _}) -> {ok, ?INVOICE_TPL}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_tpl_op_ctx(<<"UpdateInvoiceTemplate">>, ?STRING, ?STRING, ?STRING, Config),
    Req = #{
        <<"cost">> => #{
            <<"invoiceTemplateCostType">> => <<"InvoiceTemplateCostFixed">>,
            <<"amount">> => ?INTEGER,
            <<"currency">> => ?RUB
        },
        <<"lifetime">> => get_lifetime(),
        <<"product">> => <<"test_invoice_template_product">>,
        <<"description">> => <<"test_invoice_template_description">>,
        <<"metadata">> => #{<<"invoice_template_dummy_metadata">> => <<"test_value">>}
    },
    {ok, _} = capi_client_invoice_templates:update(?config(context, Config), ?STRING, Req).

-spec delete_invoice_template_ok_test(config()) -> _.
delete_invoice_template_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoice_templating, fun
                ('Get', {_, ?STRING}) -> {ok, ?INVOICE_TPL};
                ('Delete', {_, ?STRING}) -> {ok, ok}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_tpl_op_ctx(<<"DeleteInvoiceTemplate">>, ?STRING, ?STRING, ?STRING, Config),
    ok = capi_client_invoice_templates:delete(?config(context, Config), ?STRING).

-spec get_invoice_payment_methods_by_tpl_id_ok_test(config()) -> _.
get_invoice_payment_methods_by_tpl_id_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetRevision', _) -> {ok, ?INTEGER} end},
            {'invoice_templating', fun
                ('Get', {_, ?STRING}) -> {ok, ?INVOICE_TPL};
                ('ComputeTerms', {_, ?STRING, _, _}) -> {ok, ?TERM_SET}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_tpl_op_ctx(
        <<"GetInvoicePaymentMethodsByTemplateID">>,
        ?STRING,
        ?STRING,
        ?STRING,
        Config
    ),
    {ok, _} = capi_client_invoice_templates:get_invoice_payment_methods(?config(context, Config), ?STRING).

-spec get_account_by_id_ok_test(config()) -> _.
get_account_by_id_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetAccountState', _) -> {ok, ?ACCOUNT_STATE} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"GetAccountByID">>, ?STRING, Config),
    {ok, _} = capi_client_accounts:get_account_by_id(?config(context, Config), ?INTEGER).

-spec create_payment_ok_test(config()) -> _.
create_payment_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) ->
                    {ok, ?PAYPROC_INVOICE};
                ('StartPayment', {_, ?STRING, ?PAYMENT_PARAMS(<<"payment_key">>)}) ->
                    {ok, ?PAYPROC_PAYMENT}
            end},
            {bender, fun
                ('GenerateID', {_, {sequence, _}, _}) ->
                    {ok, capi_ct_helper_bender:get_result(<<"payment_key">>)};
                ('GenerateID', {_, {constant, _}, _}) ->
                    {ok, capi_ct_helper_bender:get_result(<<"session_key">>)}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"CreatePayment">>, ?STRING, ?STRING, ?STRING, Config),
    PaymentToolToken = ?TEST_PAYMENT_TOKEN,
    Req2 = #{
        <<"flow">> => #{<<"type">> => <<"PaymentFlowInstant">>},
        <<"payer">> => #{
            <<"payerType">> => <<"PaymentResourcePayer">>,
            <<"paymentSession">> => ?TEST_PAYMENT_SESSION,
            <<"paymentToolToken">> => PaymentToolToken,
            <<"contactInfo">> => #{
                <<"email">> => <<"bla@bla.ru">>
            }
        }
    },
    {ok, _} = capi_client_payments:create_payment(?config(context, Config), Req2, ?STRING).

-spec create_payment_expired_test(config()) -> _.
create_payment_expired_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"CreatePayment">>, ?STRING, ?STRING, ?STRING, Config),
    PaymentTool = {bank_card, ?BANK_CARD},
    ValidUntil = capi_utils:deadline_from_timeout(0),
    PaymentToolToken = capi_crypto:create_encrypted_payment_tool_token(PaymentTool, ValidUntil),
    Req = #{
        <<"externalID">> => <<"merch_id">>,
        <<"flow">> => #{<<"type">> => <<"PaymentFlowInstant">>},
        <<"payer">> => #{
            <<"payerType">> => <<"PaymentResourcePayer">>,
            <<"paymentSession">> => ?TEST_PAYMENT_SESSION,
            <<"paymentToolToken">> => PaymentToolToken,
            <<"contactInfo">> => #{
                <<"email">> => <<"bla@bla.ru">>
            }
        },
        <<"metadata">> => ?JSON,
        <<"processingDeadline">> => <<"5m">>
    },
    Resp = capi_client_payments:create_payment(?config(context, Config), Req, ?STRING),
    {error, {400, #{<<"code">> := <<"invalidPaymentToolToken">>}}} = Resp.

-spec create_payment_with_encrypt_token_ok_test(config()) -> _.
create_payment_with_encrypt_token_ok_test(Config) ->
    Tid = capi_ct_helper_bender:create_storage(),
    BenderKey = <<"payment_key">>,
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) ->
                    {ok, ?PAYPROC_INVOICE};
                ('StartPayment', {_, ?STRING, ?PAYMENT_PARAMS(<<"payment_key">>)}) ->
                    {ok, ?PAYPROC_PAYMENT}
            end},
            {bender, fun
                ('GenerateID', {_, {sequence, _}, CtxMsgPack}) ->
                    capi_ct_helper_bender:get_internal_id(Tid, BenderKey, CtxMsgPack);
                ('GenerateID', {_, {constant, _}, _}) ->
                    {ok, capi_ct_helper_bender:get_result(<<"session_key">>)}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"CreatePayment">>, ?STRING, ?STRING, ?STRING, Config),
    Payer = #{
        <<"payerType">> => <<"PaymentResourcePayer">>,
        <<"paymentSession">> => ?TEST_PAYMENT_SESSION,
        <<"contactInfo">> => #{
            <<"email">> => <<"bla@bla.ru">>
        }
    },
    Req1 = #{
        <<"flow">> => #{<<"type">> => <<"PaymentFlowInstant">>},
        <<"payer">> => Payer#{<<"paymentToolToken">> => get_encrypted_token()}
    },
    Req2 = #{
        <<"flow">> => #{<<"type">> => <<"PaymentFlowInstant">>},
        <<"payer">> => Payer#{<<"paymentToolToken">> => get_encrypted_token()}
    },
    {ok, Payment} = capi_client_payments:create_payment(?config(context, Config), Req1, ?STRING),
    {ok, Payment} = capi_client_payments:create_payment(?config(context, Config), Req2, ?STRING),
    capi_ct_helper_bender:del_storage(Tid).

get_encrypted_token() ->
    PaymentTool =
        {bank_card, #domain_BankCard{
            token = <<"4111111111111111">>,
            payment_system_deprecated = mastercard,
            bin = <<>>,
            last_digits = <<"1111">>,
            cardholder_name = <<"Degus Degusovich">>
        }},
    capi_crypto:create_encrypted_payment_tool_token(PaymentTool, undefined).

-spec get_payments_ok_test(config()) -> _.
get_payments_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_invoice_op_ctx(<<"GetPayments">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_payments:get_payments(?config(context, Config), ?STRING).

-spec get_payment_by_id_ok_test(config()) -> _.
get_payment_by_id_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"GetPaymentByID">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_payments:get_payment_by_id(?config(context, Config), ?STRING, ?STRING).

-spec get_payment_by_id_error_test(config()) -> _.
get_payment_by_id_error_test(Config) ->
    Failure =
        payproc_errors:construct(
            'PaymentFailure',
            {authorization_failed,
                {payment_tool_rejected, {bank_card_rejected, {cvv_invalid, #payprocerr_GeneralFailure{}}}}},
            <<"Reason">>
        ),
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', {_, ?STRING, _}) ->
                {ok, ?PAYPROC_INVOICE([?PAYPROC_FAILED_PAYMENT({failure, Failure})])}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"GetPaymentByID">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    {ok, #{
        <<"error">> := #{
            <<"message">> := <<"authorization_failed:payment_tool_rejected:bank_card_rejected:cvv_invalid">>
        }
    }} = capi_client_payments:get_payment_by_id(?config(context, Config), ?STRING, ?STRING).

-spec create_refund(config()) -> _.
create_refund(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])};
                ('RefundPayment', {_, ?STRING, ?STRING, _}) -> {ok, ?REFUND_DOMAIN}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"CreateRefund">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    Req = #{<<"reason">> => ?STRING},
    {ok, _} = capi_client_payments:create_refund(?config(context, Config), Req, ?STRING, ?STRING).

-spec create_refund_idemp_ok_test(config()) -> _.
create_refund_idemp_ok_test(Config) ->
    BenderKey = <<"bender_key">>,
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(BenderKey)} end},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) ->
                    {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])};
                ('RefundPayment', {_, ?STRING, ?STRING, ?REFUND_PARAMS(ID)}) ->
                    {ok, ?REFUND_DOMAIN(ID)}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"CreateRefund">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    Req = #{
        <<"reason">> => ?STRING,
        <<"id">> => ?STRING
    },
    {ok, Refund} = capi_client_payments:create_refund(?config(context, Config), Req, ?STRING, ?STRING),
    {ok, Refund2} = capi_client_payments:create_refund(?config(context, Config), Req, ?STRING, ?STRING),
    ?assertEqual(BenderKey, maps:get(<<"id">>, Refund)),
    ?assertEqual(Refund, Refund2).

-spec create_partial_refund(config()) -> _.
create_partial_refund(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) ->
                    {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])};
                ('RefundPayment', {_, ?STRING, ?STRING, ?REFUND_PARAMS(_, ?INTEGER, ?RUB)}) ->
                    {ok, ?REFUND_DOMAIN}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"CreateRefund">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    Req = #{
        <<"reason">> => ?STRING,
        <<"currency">> => ?RUB,
        <<"amount">> => ?INTEGER
    },
    {ok, _} = capi_client_payments:create_refund(?config(context, Config), Req, ?STRING, ?STRING).

-spec create_partial_refund_without_currency(config()) -> _.
create_partial_refund_without_currency(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) ->
                    {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])};
                ('GetPayment', _) ->
                    {ok, ?PAYPROC_PAYMENT};
                ('RefundPayment', _) ->
                    {ok, ?REFUND_DOMAIN}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"CreateRefund">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    Req = #{
        <<"reason">> => ?STRING,
        <<"amount">> => ?INTEGER
    },
    {ok, _} = capi_client_payments:create_refund(?config(context, Config), Req, ?STRING, ?STRING).

-spec get_refund_by_id(config()) -> _.
get_refund_by_id(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_REFUND_OP(<<"GetRefundByID">>, ?STRING, ?STRING, ?STRING)),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    invoice = ?CTX_INVOICE(?STRING, ?STRING, ?STRING, [?CTX_PAYMENT(?STRING)])
                }
            }
        ),
        Config
    ),
    {ok, _} = capi_client_payments:get_refund_by_id(?config(context, Config), ?STRING, ?STRING, ?STRING).

-spec get_refunds(config()) -> _.
get_refunds(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])};
                ('GetPayment', {_, ?STRING, ?STRING}) -> {ok, ?PAYPROC_PAYMENT}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"GetRefunds">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_payments:get_refunds(?config(context, Config), ?STRING, ?STRING).

-spec cancel_payment_ok_test(config()) -> _.
cancel_payment_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])};
                ('CancelPayment', {_, ?STRING, ?STRING, _}) -> {ok, ok}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"CancelPayment">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    ok = capi_client_payments:cancel_payment(?config(context, Config), ?STRING, ?STRING, ?STRING).

-spec capture_payment_ok_test(config()) -> _.
capture_payment_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun
                ('Get', {_, ?STRING, _}) -> {ok, ?PAYPROC_INVOICE([?PAYPROC_PAYMENT])};
                ('CapturePaymentNew', {_, ?STRING, ?STRING, _}) -> {ok, ok}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_payment_op_ctx(<<"CapturePayment">>, ?STRING, ?STRING, ?STRING, ?STRING, Config),
    ok = capi_client_payments:capture_payment(?config(context, Config), ?STRING, ?STRING, ?STRING).

-spec get_my_party_ok_test(config()) -> _.
get_my_party_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> {ok, ?PARTY} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"GetMyParty">>, ?STRING, Config),
    {ok, _} = capi_client_parties:get_my_party(?config(context, Config)).

-spec suspend_my_party_ok_test(config()) -> _.
suspend_my_party_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Suspend', _) -> {ok, ok} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"SuspendMyParty">>, ?STRING, Config),
    ok = capi_client_parties:suspend_my_party(?config(context, Config)).

-spec activate_my_party_ok_test(config()) -> _.
activate_my_party_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Activate', _) -> {ok, ok} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"ActivateMyParty">>, ?STRING, Config),
    ok = capi_client_parties:activate_my_party(?config(context, Config)).

-spec get_shop_by_id_ok_test(config()) -> _.
get_shop_by_id_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetShop', _) -> {ok, ?SHOP} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"GetShopByID">>, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_shops:get_shop_by_id(?config(context, Config), ?STRING).

-spec get_shops_ok_test(config()) -> _.
get_shops_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> {ok, ?PARTY} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"GetShops">>, ?STRING, Config),
    {ok, _} = capi_client_shops:get_shops(?config(context, Config)).

-spec suspend_shop_ok_test(config()) -> _.
suspend_shop_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('SuspendShop', _) -> {ok, ok} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"SuspendShop">>, ?STRING, ?STRING, Config),
    ok = capi_client_shops:suspend_shop(?config(context, Config), ?STRING).

-spec activate_shop_ok_test(config()) -> _.
activate_shop_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('ActivateShop', _) -> {ok, ok} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"ActivateShop">>, ?STRING, ?STRING, Config),
    ok = capi_client_shops:activate_shop(?config(context, Config), ?STRING).

-spec get_claim_by_id_ok_test(config()) -> _.
get_claim_by_id_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetClaim', _) -> {ok, ?CLAIM(?CLAIM_CHANGESET)} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_claim_op_ctx(<<"GetClaimByID">>, ?STRING, ?INTEGER_BINARY, Config),
    {ok, _} = capi_client_claims:get_claim_by_id(?config(context, Config), ?INTEGER_BINARY).

-spec get_claims_ok_test(config()) -> _.
get_claims_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetClaims', _) ->
                {ok, [
                    ?CLAIM(?CLAIM_CHANGESET),
                    ?CLAIM(?CONTRACTOR_CLAIM_CHANGESET),
                    ?CLAIM(?WALLET_CLAIM_CHANGESET)
                ]}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"GetClaims">>, ?STRING, Config),
    {ok, [_OnlyOneClaim]} = capi_client_claims:get_claims(?config(context, Config)).

-spec revoke_claim_ok_test(config()) -> _.
revoke_claim_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('RevokeClaim', _) -> {ok, ok} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_claim_op_ctx(<<"RevokeClaimByID">>, ?STRING, ?INTEGER_BINARY, Config),
    ok = capi_client_claims:revoke_claim_by_id(?config(context, Config), ?STRING, ?INTEGER_BINARY, ?INTEGER_BINARY).

-spec create_claim_ok_test(config()) -> _.
create_claim_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('CreateClaim', _) -> {ok, ?CLAIM(?CLAIM_CHANGESET)} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"CreateClaim">>, ?STRING, Config),
    Changeset = [
        #{
            <<"partyModificationType">> => <<"ContractModification">>,
            <<"contractID">> => ?STRING,
            <<"contractModificationType">> => <<"ContractCreation">>,
            <<"contractor">> => #{
                <<"contractorType">> => <<"LegalEntity">>,
                <<"entityType">> => <<"RussianLegalEntity">>,
                <<"registeredName">> => <<"testRegisteredName">>,
                <<"registeredNumber">> => <<"1234567890123">>,
                <<"inn">> => <<"1234567890">>,
                <<"actualAddress">> => <<"testActualAddress">>,
                <<"postAddress">> => <<"testPostAddress">>,
                <<"representativePosition">> => <<"testRepresentativePosition">>,
                <<"representativeFullName">> => <<"testRepresentativeFullName">>,
                <<"representativeDocument">> => <<"testRepresentativeDocument">>,
                <<"bankAccount">> => #{
                    <<"account">> => <<"12345678901234567890">>,
                    <<"bankName">> => <<"testBankName">>,
                    <<"bankPostAccount">> => <<"12345678901234567890">>,
                    <<"bankBik">> => <<"123456789">>
                }
            }
        },
        #{
            <<"partyModificationType">> => <<"ContractModification">>,
            <<"contractID">> => <<"PrivateEntityContract">>,
            <<"contractModificationType">> => <<"ContractCreation">>,
            <<"contractor">> => #{
                <<"contractorType">> => <<"PrivateEntity">>,
                <<"entityType">> => <<"RussianPrivateEntity">>,
                <<"firstName">> => ?STRING,
                <<"secondName">> => ?STRING,
                <<"middleName">> => ?STRING,
                <<"contactInfo">> => #{}
            },
            <<"paymentInstitutionID">> => ?INTEGER
        },
        #{
            <<"partyModificationType">> => <<"ContractModification">>,
            <<"contractID">> => ?STRING,
            <<"contractModificationType">> => <<"ContractPayoutToolCreation">>,
            <<"payoutToolID">> => ?STRING,
            <<"currency">> => ?RUB,
            <<"details">> => #{
                <<"detailsType">> => <<"PayoutToolDetailsBankAccount">>,
                <<"account">> => <<"12345678901234567890">>,
                <<"bankName">> => <<"testBankName">>,
                <<"bankPostAccount">> => <<"12345678901234567890">>,
                <<"bankBik">> => <<"123456789">>
            }
        },
        #{
            <<"partyModificationType">> => <<"ContractModification">>,
            <<"contractID">> => ?STRING,
            <<"contractModificationType">> => <<"ContractLegalAgreementBinding">>,
            <<"legalAgreement">> => #{
                <<"id">> => ?STRING,
                <<"signedAt">> => ?TIMESTAMP,
                <<"validUntil">> => ?TIMESTAMP
            }
        },
        #{
            <<"partyModificationType">> => <<"ContractModification">>,
            <<"contractID">> => ?STRING,
            <<"contractModificationType">> => <<"ContractReportingPreferencesChange">>,
            <<"serviceAcceptanceActPreferences">> => #{
                <<"scheduleID">> => ?INTEGER,
                <<"signer">> => #{
                    <<"position">> => ?STRING,
                    <<"fullName">> => ?STRING,
                    <<"document">> => #{<<"representativeDocumentType">> => <<"ArticlesOfAssociation">>}
                }
            }
        }
    ],
    {ok, _} = capi_client_claims:create_claim(?config(context, Config), Changeset).

-spec update_claim_by_id_test(config()) -> _.
update_claim_by_id_test(_) ->
    % Not realised yet.
    ok.

-spec get_contract_by_id_ok_test(config()) -> _.
get_contract_by_id_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> {ok, ?PARTY} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_CONTRACT_OP(<<"GetContractByID">>, ?STRING, _))
            }
        ),
        Config
    ),
    {ok, _} = capi_client_contracts:get_contract_by_id(?config(context, Config), ?STRING),
    {ok, _} = capi_client_contracts:get_contract_by_id(?config(context, Config), ?WALLET_CONTRACT_ID).

-spec get_contracts_ok_test(config()) -> _.
get_contracts_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('Get', _) -> {ok, ?PARTY} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"GetContracts">>, ?STRING, Config),
    {ok, [_First, _Second]} = capi_client_contracts:get_contracts(?config(context, Config)).

-spec get_contract_adjustments_ok_test(config()) -> _.
get_contract_adjustments_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetContract', _) -> {ok, ?CONTRACT} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_contract_op_ctx(<<"GetContractAdjustments">>, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_contracts:get_contract_adjustments(?config(context, Config), ?STRING).

-spec get_contract_adjustment_by_id_ok_test(config()) -> _.
get_contract_adjustment_by_id_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetContract', _) -> {ok, ?CONTRACT} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_contract_op_ctx(<<"GetContractAdjustmentByID">>, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_contracts:get_contract_adjustment_by_id(?config(context, Config), ?STRING, ?STRING).

-spec get_payout_tools_ok_test(config()) -> _.
get_payout_tools_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetContract', _) -> {ok, ?CONTRACT} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_contract_op_ctx(<<"GetPayoutTools">>, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_payouts:get_payout_tools(?config(context, Config), ?STRING).

-spec get_payout_tool_by_id(config()) -> _.
get_payout_tool_by_id(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetContract', _) -> {ok, ?CONTRACT} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_contract_op_ctx(<<"GetPayoutToolByID">>, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_payouts:get_payout_tool_by_id(?config(context, Config), ?STRING, ?BANKID_RU),
    {ok, _} = capi_client_payouts:get_payout_tool_by_id(?config(context, Config), ?STRING, ?BANKID_US).

-spec create_webhook_ok_test(config()) -> _.
create_webhook_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('GetShop', _) -> {ok, ?SHOP} end},
            {webhook_manager, fun('Create', _) -> {ok, ?WEBHOOK} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"CreateWebhook">>, ?STRING, Config),
    Req = #{
        <<"url">> => <<"http://localhost:8080/TODO">>,
        <<"scope">> => #{
            <<"topic">> => <<"InvoicesTopic">>,
            <<"shopID">> => ?STRING,
            <<"eventTypes">> => []
        }
    },
    {ok, _} = capi_client_webhooks:create_webhook(?config(context, Config), Req).

-spec get_webhooks(config()) -> _.
get_webhooks(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {webhook_manager, fun('GetList', _) -> {ok, [?WEBHOOK]} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_party_op_ctx(<<"GetWebhooks">>, ?STRING, Config),
    {ok, _} = capi_client_webhooks:get_webhooks(?config(context, Config)).

-spec get_webhook_by_id(config()) -> _.
get_webhook_by_id(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {webhook_manager, fun('Get', _) -> {ok, ?WEBHOOK} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_webhook_op_ctx(<<"GetWebhookByID">>, ?INTEGER_BINARY, ?STRING, Config),
    {ok, _} = capi_client_webhooks:get_webhook_by_id(?config(context, Config), ?INTEGER_BINARY).

-spec delete_webhook_by_id(config()) -> _.
delete_webhook_by_id(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {webhook_manager, fun
                ('Get', _) -> {ok, ?WEBHOOK};
                ('Delete', _) -> {ok, ok}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_webhook_op_ctx(<<"DeleteWebhookByID">>, ?INTEGER_BINARY, ?STRING, Config),
    ok = capi_client_webhooks:delete_webhook_by_id(?config(context, Config), ?INTEGER_BINARY).

-spec get_locations_names_ok_test(config()) -> _.
get_locations_names_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {geo_ip_service, fun('GetLocationName', _) -> {ok, #{123 => ?STRING}} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_op_ctx(<<"GetLocationsNames">>, Config),
    Query = #{
        <<"geoIDs">> => <<"5,3,6,5,4">>,
        <<"language">> => <<"ru">>
    },
    {ok, _} = capi_client_geo:get_location_names(?config(context, Config), Query).

-spec search_invoices_ok_test(config()) -> _.
search_invoices_ok_test(Config) ->
    QueryInvoiceID = <<"testInvoiceID">>,
    QueryPaymentID = <<"testPaymentID">>,
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', {_, ID, _}) when ID == QueryInvoiceID -> {ok, ?PAYPROC_INVOICE} end},
            {merchant_stat, fun('GetInvoices', _) -> {ok, ?STAT_RESPONSE_INVOICES} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(#bctx_v1_CommonAPIOperation{
                    id = <<"SearchInvoices">>,
                    party = ?CTX_ENTITY(?STRING),
                    invoice = ?CTX_ENTITY(QueryInvoiceID),
                    payment = ?CTX_ENTITY(QueryPaymentID)
                }),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    invoice = ?CTX_INVOICE(_, _, _)
                }
            }
        ),
        Config
    ),
    Query = [
        {limit, 2},
        {offset, 2},
        {from_time, {{2015, 08, 11}, {19, 42, 35}}},
        {to_time, {{2020, 08, 11}, {19, 42, 35}}},
        {invoiceStatus, <<"fulfilled">>},
        {payerEmail, <<"test@test.ru">>},
        {payerIP, <<"192.168.0.1">>},
        {paymentStatus, <<"processed">>},
        {paymentFlow, <<"instant">>},
        {paymentMethod, <<"bankCard">>},
        {invoiceID, QueryInvoiceID},
        {paymentID, QueryPaymentID},
        {payerFingerprint, <<"blablablalbalbal">>},
        {lastDigits, <<"2222">>},
        {bin, <<"424242">>},
        {bankCardTokenProvider, <<"applepay">>},
        {bankCardPaymentSystem, <<"visa">>},
        {paymentAmount, 10000}
    ],
    {ok, _, _} = capi_client_searches:search_invoices(?config(context, Config), ?STRING, Query).

-spec search_payments_ok_test(config()) -> _.
search_payments_ok_test(Config) ->
    QueryInvoiceID = <<"testInvoiceID">>,
    QueryPaymentID = <<"testPaymentID">>,
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {invoicing, fun('Get', {_, ID, _}) when ID == QueryInvoiceID -> {ok, ?PAYPROC_INVOICE} end},
            {merchant_stat, fun('GetPayments', _) -> {ok, ?STAT_RESPONSE_PAYMENTS} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(#bctx_v1_CommonAPIOperation{
                    id = <<"SearchPayments">>,
                    party = ?CTX_ENTITY(?STRING),
                    invoice = ?CTX_ENTITY(QueryInvoiceID),
                    payment = ?CTX_ENTITY(QueryPaymentID)
                }),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    invoice = ?CTX_INVOICE(_, _, _)
                }
            }
        ),
        Config
    ),
    Query = [
        {limit, 2},
        {offset, 2},
        {from_time, {{2015, 08, 11}, {19, 42, 35}}},
        {to_time, {{2020, 08, 11}, {19, 42, 35}}},
        {payerEmail, <<"test@test.ru">>},
        {payerIP, <<"192.168.0.1">>},
        {paymentStatus, <<"processed">>},
        {paymentFlow, <<"instant">>},
        {paymentMethod, <<"bankCard">>},
        {invoiceID, QueryInvoiceID},
        {paymentID, QueryPaymentID},
        {payerFingerprint, <<"blablablalbalbal">>},
        % {lastDigits, <<"2222">>}, %%@FIXME cannot be used until getting the newest api client
        % {bin, <<"424242">>},
        {bankCardPaymentSystem, <<"visa">>},
        {paymentAmount, 10000}
    ],
    QueryApple = lists:keystore(bankCardTokenProvider, 1, Query, {bankCardTokenProvider, <<"applepay">>}),
    QueryYandex = lists:keystore(bankCardTokenProvider, 1, Query, {bankCardTokenProvider, <<"yandexpay">>}),
    ?assertMatch(
        {ok, _, _},
        capi_client_searches:search_payments(?config(context, Config), ?STRING, QueryApple)
    ),
    ?assertMatch(
        {ok, _, _},
        capi_client_searches:search_payments(?config(context, Config), ?STRING, QueryYandex)
    ).

-spec search_payouts_ok_test(config()) -> _.
search_payouts_ok_test(Config) ->
    QueryPayoutID = <<"testPayoutID">>,
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {payout_management, fun('Get', {ID}) when ID == QueryPayoutID ->
                {ok, ?PAYOUT(?PAYOUT_BANK_ACCOUNT_RUS, [?PAYOUT_SUMMARY_ITEM])}
            end},
            {merchant_stat, fun('GetPayouts', _) -> {ok, ?STAT_RESPONSE_PAYOUTS} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(#bctx_v1_CommonAPIOperation{
                    id = <<"SearchPayouts">>,
                    party = ?CTX_ENTITY(?STRING),
                    shop = ?CTX_ENTITY(?STRING),
                    payout = ?CTX_ENTITY(QueryPayoutID)
                }),
                payouts = #bctx_v1_ContextPayouts{
                    payout = #bctx_v1_Payout{id = ?STRING, party = ?CTX_ENTITY(?STRING)}
                }
            }
        ),
        Config
    ),
    Query = [
        {limit, 2},
        {offset, 2},
        {from_time, {{2015, 08, 11}, {19, 42, 35}}},
        {to_time, {{2020, 08, 11}, {19, 42, 35}}},
        {payoutID, QueryPayoutID},
        {payoutToolType, <<"PayoutCard">>}
    ],

    {ok, _, _} = capi_client_searches:search_payouts(?config(context, Config), ?STRING, Query).

-spec get_payment_conversion_stats_ok_test(_) -> _.
get_payment_conversion_stats_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {merchant_stat, fun('GetStatistics', _) -> {ok, ?STAT_RESPONSE_RECORDS} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"GetPaymentConversionStats">>, ?STRING, ?STRING, Config),
    Query = [
        {limit, 2},
        {offset, 2},
        {from_time, {{2015, 08, 11}, {19, 42, 35}}},
        {to_time, {{2020, 08, 11}, {19, 42, 35}}},
        {split_unit, minute},
        {split_size, 1}
    ],
    {ok, _} = capi_client_analytics:get_payment_conversion_stats(?config(context, Config), ?STRING, Query).

-spec get_payment_revenue_stats_ok_test(config()) -> _.
get_payment_revenue_stats_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {merchant_stat, fun('GetStatistics', _) -> {ok, ?STAT_RESPONSE_RECORDS} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"GetPaymentRevenueStats">>, ?STRING, ?STRING, Config),
    Query = [
        {limit, 2},
        {offset, 2},
        {from_time, {{2015, 08, 11}, {19, 42, 36}}},
        {to_time, {{2020, 08, 11}, {19, 42, 36}}},
        {split_unit, minute},
        {split_size, 1}
    ],
    {ok, _} = capi_client_analytics:get_payment_revenue_stats(?config(context, Config), ?STRING, Query).

-spec get_payment_geo_stats_ok_test(config()) -> _.
get_payment_geo_stats_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {merchant_stat, fun('GetStatistics', _) -> {ok, ?STAT_RESPONSE_RECORDS} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"GetPaymentGeoStats">>, ?STRING, ?STRING, Config),
    Query = [
        {limit, 2},
        {offset, 0},
        {from_time, {{2015, 08, 11}, {19, 42, 37}}},
        {to_time, {{2020, 08, 11}, {19, 42, 37}}},
        {split_unit, minute},
        {split_size, 1}
    ],
    {ok, _} = capi_client_analytics:get_payment_geo_stats(?config(context, Config), ?STRING, Query).

-spec get_payment_rate_stats_ok_test(config()) -> _.
get_payment_rate_stats_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {merchant_stat, fun('GetStatistics', _) -> {ok, ?STAT_RESPONSE_RECORDS} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"GetPaymentRateStats">>, ?STRING, ?STRING, Config),
    Query = [
        {limit, 2},
        {offset, 0},
        {from_time, {{2015, 08, 11}, {19, 42, 38}}},
        {to_time, {{2020, 08, 11}, {19, 42, 38}}},
        {split_unit, minute},
        {split_size, 1}
    ],
    {ok, _} = capi_client_analytics:get_payment_rate_stats(?config(context, Config), ?STRING, Query).

-spec get_payment_method_stats_ok_test(config()) -> _.
get_payment_method_stats_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {merchant_stat, fun('GetStatistics', _) -> {ok, ?STAT_RESPONSE_RECORDS} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"GetPaymentMethodStats">>, ?STRING, ?STRING, Config),
    Query = [
        {limit, 2},
        {offset, 0},
        {from_time, {{2015, 08, 11}, {19, 42, 39}}},
        {to_time, {{2020, 08, 11}, {19, 42, 39}}},
        {split_unit, minute},
        {split_size, 1},
        {paymentMethod, <<"bankCard">>}
    ],
    {ok, _} = capi_client_analytics:get_payment_method_stats(?config(context, Config), ?STRING, Query).

-spec get_reports_ok_test(config()) -> _.
get_reports_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {reporting, fun('GetReports', _) -> {ok, ?FOUND_REPORTS} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"GetReports">>, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_reports:get_reports(?config(context, Config), ?STRING, ?TIMESTAMP, ?TIMESTAMP).

-spec download_report_file_ok_test(_) -> _.
download_report_file_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {reporting, fun
                ('GetReport', _) -> {ok, ?REPORT};
                ('GeneratePresignedUrl', _) -> {ok, ?STRING}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(#bctx_v1_CommonAPIOperation{
                    id = <<"DownloadFile">>,
                    shop = ?CTX_ENTITY(?STRING),
                    report = ?CTX_ENTITY(?INTEGER_BINARY),
                    file = ?CTX_ENTITY(?STRING)
                }),
                reports = #bctx_v1_ContextReports{
                    report = ?CTX_REPORT(?INTEGER_BINARY, ?STRING, ?STRING, [?CTX_ENTITY(?STRING)])
                }
            }
        ),
        Config
    ),
    {ok, _} = capi_client_reports:download_file(?config(context, Config), ?STRING, ?INTEGER_BINARY, ?STRING).

-spec download_report_file_not_found_test(_) -> _.
download_report_file_not_found_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {reporting, fun
                ('GetReport', _) -> {ok, ?REPORT#reports_Report{status = pending}};
                ('GeneratePresignedUrl', _) -> {ok, ?STRING}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(#bctx_v1_CommonAPIOperation{
                    id = <<"DownloadFile">>,
                    shop = ?CTX_ENTITY(?STRING),
                    report = ?CTX_ENTITY(?INTEGER_BINARY),
                    file = ?CTX_ENTITY(?STRING)
                }),
                reports = #bctx_v1_ContextReports{
                    report = ?CTX_REPORT(?INTEGER_BINARY, ?STRING, ?STRING, [?CTX_ENTITY(?STRING)])
                }
            }
        ),
        Config
    ),
    {error, {404, #{<<"message">> := <<"Report not found">>}}} =
        capi_client_reports:download_file(?config(context, Config), ?STRING, ?INTEGER_BINARY, ?STRING).

-spec get_categories_ok_test(config()) -> _.
get_categories_ok_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    _ = mock_bouncer_assert_op_ctx(<<"GetCategories">>, Config),
    {ok, _} = capi_client_categories:get_categories(?config(context, Config)).

-spec get_category_by_ref_ok_test(config()) -> _.
get_category_by_ref_ok_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    _ = mock_bouncer_assert_op_ctx(<<"GetCategoryByRef">>, Config),
    {ok, _} = capi_client_categories:get_category_by_ref(?config(context, Config), ?INTEGER).

-spec get_schedule_by_ref_ok_test(config()) -> _.
get_schedule_by_ref_ok_test(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    _ = mock_bouncer_assert_op_ctx(<<"GetScheduleByRef">>, Config),
    {ok, _} = capi_client_payouts:get_schedule_by_ref(?config(context, Config), ?INTEGER).

-spec get_payment_institutions(config()) -> _.
get_payment_institutions(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    _ = mock_bouncer_assert_op_ctx(<<"GetPaymentInstitutions">>, Config),
    {ok, [_Something]} = capi_client_payment_institutions:get_payment_institutions(?config(context, Config)),
    {ok, []} =
        capi_client_payment_institutions:get_payment_institutions(?config(context, Config), <<"RUS">>, <<"live">>),
    {ok, [#{<<"realm">> := <<"test">>}]} =
        capi_client_payment_institutions:get_payment_institutions(?config(context, Config), <<"RUS">>, <<"test">>).

-spec get_payment_institution_by_ref(config()) -> _.
get_payment_institution_by_ref(Config) ->
    _ = mock_woody_client([{token_keeper, fun capi_ct_helper_tk:user_session_handler/2}], Config),
    _ = mock_bouncer_assert_op_ctx(<<"GetPaymentInstitutionByRef">>, Config),
    {ok, _} = capi_client_payment_institutions:get_payment_institution_by_ref(?config(context, Config), ?INTEGER).

-spec get_payment_institution_payment_terms(config()) -> _.
get_payment_institution_payment_terms(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('ComputePaymentInstitutionTerms', _) -> {ok, ?TERM_SET} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_op_ctx(<<"GetPaymentInstitutionPaymentTerms">>, Config),
    {ok, _} =
        capi_client_payment_institutions:get_payment_institution_payment_terms(?config(context, Config), ?INTEGER).

-spec get_payment_institution_payout_methods(config()) -> _.
get_payment_institution_payout_methods(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('ComputePaymentInstitutionTerms', _) -> {ok, ?TERM_SET} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_op_ctx(<<"GetPaymentInstitutionPayoutMethods">>, Config),
    {ok, _} = capi_client_payment_institutions:get_payment_institution_payout_methods(
        ?config(context, Config),
        ?INTEGER,
        <<"RUB">>
    ).

-spec get_payment_institution_payout_schedules(config()) -> _.
get_payment_institution_payout_schedules(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {party_management, fun('ComputePaymentInstitutionTerms', _) -> {ok, ?TERM_SET} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_op_ctx(<<"GetPaymentInstitutionPayoutSchedules">>, Config),
    {ok, _} = capi_client_payment_institutions:get_payment_institution_payout_schedules(
        ?config(context, Config),
        ?INTEGER,
        <<"USD">>,
        <<"BankAccount">>
    ).

-spec create_customer_ok_test(config()) -> _.
create_customer_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun('Create', _) -> {ok, ?CUSTOMER} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_shop_op_ctx(<<"CreateCustomer">>, ?STRING, ?STRING, Config),
    Req = #{
        <<"shopID">> => ?STRING,
        <<"contactInfo">> => #{<<"email">> => <<"bla@bla.ru">>},
        <<"metadata">> => #{<<"text">> => [<<"SOMESHIT">>, 42]}
    },
    {ok, _} = capi_client_customers:create_customer(?config(context, Config), Req).

-spec get_customer_ok_test(config()) -> _.
get_customer_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun('Get', _) -> {ok, ?CUSTOMER} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_customer_op_ctx(<<"GetCustomerById">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_customers:get_customer_by_id(?config(context, Config), ?STRING).

-spec create_customer_access_token_ok_test(config()) -> _.
create_customer_access_token_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun('Get', _) -> {ok, ?CUSTOMER} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_customer_op_ctx(<<"CreateCustomerAccessToken">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_customers:create_customer_access_token(?config(context, Config), ?STRING).

-spec create_binding_ok_test(config()) -> _.
create_binding_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
            {customer_management, fun
                ('Get', {?STRING, _}) -> {ok, ?CUSTOMER};
                ('StartBinding', {?STRING, _}) -> {ok, ?CUSTOMER_BINDING}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_customer_op_ctx(<<"CreateBinding">>, ?STRING, ?STRING, ?STRING, Config),
    PaymentToolToken = ?TEST_PAYMENT_TOKEN,
    Req2 = #{
        <<"paymentResource">> => #{
            <<"paymentSession">> => ?TEST_PAYMENT_SESSION,
            <<"paymentToolToken">> => PaymentToolToken
        }
    },
    {ok, _} = capi_client_customers:create_binding(?config(context, Config), ?STRING, Req2).

-spec create_binding_expired_test(config()) -> _.
create_binding_expired_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun('Get', {?STRING, _}) -> {ok, ?CUSTOMER} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_customer_op_ctx(<<"CreateBinding">>, ?STRING, ?STRING, ?STRING, Config),
    PaymentTool = {bank_card, ?BANK_CARD},
    ValidUntil = capi_utils:deadline_from_timeout(0),
    PaymentToolToken = capi_crypto:create_encrypted_payment_tool_token(PaymentTool, ValidUntil),
    Req = #{
        <<"paymentResource">> => #{
            <<"paymentSession">> => ?TEST_PAYMENT_SESSION,
            <<"paymentToolToken">> => PaymentToolToken
        }
    },
    Resp = capi_client_customers:create_binding(?config(context, Config), ?STRING, Req),
    {error, {400, #{<<"code">> := <<"invalidPaymentToolToken">>}}} = Resp.

-spec get_bindings_ok_test(config()) -> _.
get_bindings_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun('Get', _) -> {ok, ?CUSTOMER} end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_customer_op_ctx(<<"GetBindings">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_customers:get_bindings(?config(context, Config), ?STRING).

-spec get_binding_ok_test(config()) -> _.
get_binding_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun('Get', _) -> {ok, ?CUSTOMER} end}
        ],
        Config
    ),
    _ = mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_BINDING_OP(<<"GetBinding">>, ?STRING, ?STRING)),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    customer = ?CTX_CUSTOMER(?STRING, ?STRING, ?STRING)
                }
            }
        ),
        Config
    ),
    {ok, _} = capi_client_customers:get_binding(?config(context, Config), ?STRING, ?STRING).

-spec get_customer_events_ok_test(config()) -> _.
get_customer_events_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun
                ('Get', {?STRING, _}) -> {ok, ?CUSTOMER};
                ('GetEvents', _) -> {ok, []}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_customer_op_ctx(<<"GetCustomerEvents">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_customers:get_customer_events(?config(context, Config), ?STRING, 10).

-spec delete_customer_ok_test(config()) -> _.
delete_customer_ok_test(Config) ->
    _ = mock_woody_client(
        [
            {token_keeper, fun capi_ct_helper_tk:user_session_handler/2},
            {customer_management, fun
                ('Get', {?STRING, _}) -> {ok, ?CUSTOMER};
                ('Delete', _) -> {ok, ok}
            end}
        ],
        Config
    ),
    _ = mock_bouncer_assert_customer_op_ctx(<<"DeleteCustomer">>, ?STRING, ?STRING, ?STRING, Config),
    {ok, _} = capi_client_customers:delete_customer(?config(context, Config), ?STRING).

-spec check_support_decrypt_v1_test(config()) -> _.
check_support_decrypt_v1_test(_Config) ->
    PaymentToolToken = <<
        "v1.eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJhbGciOiJFQ0RILUVTIiwiY3J2IjoiUC0yNTYiLCJrdHkiOi"
        "JFQyIsInVzZSI6ImVuYyIsIngiOiJaN0xCNXprLUtIaUd2OV9PS2lYLUZ6d1M3bE5Ob25iQm8zWlJnaWkxNEFBIiwieSI6IlFTdWVSb2I"
        "tSjhJV1pjTmptRWxFMWlBckt4d1lHeFg5a01FMloxSXJKNVUifSwia2lkIjoia3hkRDBvclZQR29BeFdycUFNVGVRMFU1TVJvSzQ3dVp4"
        "V2lTSmRnbzB0MCJ9..Zf3WXHtg0cg_Pg2J.wi8sq9RWZ-SO27G1sRrHAsJUALdLGniGGXNOtIGtLyppW_NYF3TSPJ-ehYzy.vRLMAbWtd"
        "uC6jBO6F7-t_A"
    >>,
    {ok, {PaymentTool, ValidUntil}} = capi_crypto:decrypt_payment_tool_token(PaymentToolToken),
    ?assertEqual(
        {mobile_commerce, #domain_MobileCommerce{
            phone = #domain_MobilePhone{
                cc = <<"7">>,
                ctn = <<"9210001122">>
            },
            operator_deprecated = megafone
        }},
        PaymentTool
    ),
    ?assertEqual(undefined, ValidUntil).

-spec check_support_decrypt_v2_test(config()) -> _.
check_support_decrypt_v2_test(_Config) ->
    PaymentToolToken = <<
        "v2.eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOEdDTSIsImVwayI6eyJhbGciOiJFQ0RILUVTIiwiY3J2IjoiUC0yNTYiLCJrdHkiOi"
        "JFQyIsInVzZSI6ImVuYyIsIngiOiJRanFmNFVrOTJGNzd3WXlEUjNqY3NwR2dpYnJfdVRmSXpMUVplNzVQb1R3IiwieSI6InA5cjJGV3F"
        "mU2xBTFJXYWhUSk8xY3VneVZJUXVvdzRwMGdHNzFKMFJkUVEifSwia2lkIjoia3hkRDBvclZQR29BeFdycUFNVGVRMFU1TVJvSzQ3dVp4"
        "V2lTSmRnbzB0MCJ9..j3zEyCqyfQjpEtQM.JAc3kqJm6zbn0fMZGlK_t14Yt4PvgOuoVL2DtkEgIXIqrxxWFbykKBGxQvwYisJYIUJJwt"
        "YbwvuGEODcK2uTC2quPD2Ejew66DLJF2xcAwE.MNVimzi8r-5uTATNalgoBQ"
    >>,
    {ok, {PaymentTool, ValidUntil}} = capi_crypto:decrypt_payment_tool_token(PaymentToolToken),
    ?assertEqual(
        {mobile_commerce, #domain_MobileCommerce{
            phone = #domain_MobilePhone{
                cc = <<"7">>,
                ctn = <<"9210001122">>
            },
            operator_deprecated = megafone
        }},
        PaymentTool
    ),
    ?assertEqual(<<"2020-10-29T23:44:15.499Z">>, capi_utils:deadline_to_binary(ValidUntil)).

%%

issue_token(KeyName, UserID, ACL, LifeTime) ->
    Claims1 = #{?STRING => ?STRING},
    Claims2 = capi_authorizer_jwt:set_subject_id(UserID, Claims1),
    Claims3 = capi_authorizer_jwt:set_expires_at(get_expires_at(LifeTime), Claims2),
    Claims4 = capi_authorizer_jwt:set_acl(capi_acl:from_list(ACL), Claims3),
    capi_authorizer_jwt:issue(KeyName, Claims4).

get_expires_at({lifetime, Lt}) ->
    genlib_time:unow() + Lt;
get_expires_at({deadline, Dl}) ->
    Dl;
get_expires_at(unlimited) ->
    0.

issue_dummy_token(ACL, Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => ?STRING,
        <<"exp">> => 0,
        <<"resource_access">> => #{
            <<"common-api">> => #{
                <<"roles">> => capi_acl:encode(capi_acl:from_list(ACL))
            }
        }
    },
    BadPemFile = get_keysource("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_keysource("keys/local/capi.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

start_capi(Keyset, Config) ->
    JwkPublSource = {json, {file, get_keysource("keys/local/jwk.publ.json", Config)}},
    JwkPrivSource = {json, {file, get_keysource("keys/local/jwk.priv.json", Config)}},
    CapiEnv = [
        {ip, ?CAPI_IP},
        {port, ?CAPI_PORT},
        {deployment, ?TEST_CAPI_DEPLOYMENT},
        {graceful_shutdown_timeout, 0},
        {authorizers, #{
            jwt => #{
                signee => capi,
                keyset => Keyset
            }
        }},
        {bouncer_ruleset_id, ?TEST_RULESET_ID},
        {lechiffre_opts, #{
            encryption_source => JwkPublSource,
            decryption_sources => [JwkPrivSource]
        }},
        {token_keeper_opts, #{
            meta_namespaces => #{
                user_session => ?META_NS_USER_SESSION,
                api_key => ?META_NS_API_KEY
            }
        }}
    ],
    capi_ct_helper:start_app(capi, CapiEnv).

% TODO move it to `capi_dummy_service`, looks more appropriate
start_mocked_service_sup() ->
    {ok, SupPid} = supervisor:start_link(?MODULE, []),
    _ = unlink(SupPid),
    SupPid.

stop_mocked_service_sup(SupPid) ->
    proc_lib:stop(SupPid, shutdown, 5000).

mock_bouncer_assert_op_ctx(Op, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_CAPI_OP(Op))
            }
        ),
        Config
    ).

mock_bouncer_assert_party_op_ctx(Op, PartyID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_PARTY_OP(Op, PartyID))
            }
        ),
        Config
    ).

mock_bouncer_assert_shop_op_ctx(Op, PartyID, ShopID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_SHOP_OP(Op, PartyID, ShopID))
            }
        ),
        Config
    ).

mock_bouncer_assert_contract_op_ctx(Op, PartyID, ContractID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_CONTRACT_OP(Op, PartyID, ContractID))
            }
        ),
        Config
    ).

mock_bouncer_assert_invoice_op_ctx(Op, InvoiceID, PartyID, ShopID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_INVOICE_OP(Op, InvoiceID)),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    invoice = ?CTX_INVOICE(InvoiceID, PartyID, ShopID)
                }
            }
        ),
        Config
    ).

mock_bouncer_assert_payment_op_ctx(Op, InvoiceID, PaymentID, PartyID, ShopID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_PAYMENT_OP(Op, InvoiceID, PaymentID)),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    invoice = ?CTX_INVOICE(InvoiceID, PartyID, ShopID, [?CTX_PAYMENT(PaymentID)])
                }
            }
        ),
        Config
    ).

mock_bouncer_assert_invoice_tpl_op_ctx(Op, InvoiceTemplateID, PartyID, ShopID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_INVOICE_TPL_OP(Op, InvoiceTemplateID)),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    invoice_template = ?CTX_INVOICE_TPL(InvoiceTemplateID, PartyID, ShopID)
                }
            }
        ),
        Config
    ).

mock_bouncer_assert_customer_op_ctx(Op, CustomerID, PartyID, ShopID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_CUSTOMER_OP(Op, CustomerID)),
                payment_processing = #bctx_v1_ContextPaymentProcessing{
                    customer = ?CTX_CUSTOMER(CustomerID, PartyID, ShopID)
                }
            }
        ),
        Config
    ).

mock_bouncer_assert_claim_op_ctx(Op, PartyID, ClaimID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_CLAIM_OP(Op, PartyID, ClaimID))
            }
        ),
        Config
    ).

mock_bouncer_assert_webhook_op_ctx(Op, WebhookID, PartyID, Config) ->
    mock_bouncer_arbiter(
        ?assertContextMatches(
            #bctx_v1_ContextFragment{
                capi = ?CTX_CAPI(?CTX_WEBHOOK_OP(Op, WebhookID)),
                webhooks = #bctx_v1_ContextWebhooks{
                    webhook = ?CTX_WEBHOOK(WebhookID, PartyID)
                }
            }
        ),
        Config
    ).

mock_bouncer_arbiter(JudgeFun, SupOrConfig) ->
    start_bouncer_client(
        mock_services(
            [
                {
                    bouncer,
                    {bouncer_decisions_thrift, 'Arbiter'},
                    fun('Judge', {?TEST_RULESET_ID, Context}) ->
                        Fragments = decode_bouncer_context(Context),
                        Combined = combine_fragments(Fragments),
                        JudgeFun(Combined)
                    end
                }
            ],
            SupOrConfig
        )
    ).

mock_bouncer_client(SupOrConfig) ->
    start_bouncer_client(
        mock_services(
            [
                {
                    org_management,
                    {orgmgmt_auth_context_provider_thrift, 'AuthContextProvider'},
                    fun('GetUserContext', {UserID}) ->
                        {encoded_fragment, Fragment} = bouncer_client:bake_context_fragment(
                            bouncer_context_helpers:make_user_fragment(#{
                                id => UserID,
                                realm => #{id => ?TEST_USER_REALM},
                                orgs => [#{id => ?STRING, owner => #{id => UserID}, party => #{id => UserID}}]
                            })
                        ),
                        {ok, Fragment}
                    end
                }
            ],
            SupOrConfig
        )
    ).

decode_bouncer_context(#bdcs_Context{fragments = Fragments}) ->
    maps:map(fun(_, Fragment) -> decode_bouncer_fragment(Fragment) end, Fragments).

decode_bouncer_fragment(#bctx_ContextFragment{type = v1_thrift_binary, content = Content}) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Content),
    {ok, Fragment, _} = thrift_strict_binary_codec:read(Codec, Type),
    Fragment.

judge_always_allowed() ->
    fun(_) -> {ok, ?JUDGEMENT(?ALLOWED)} end.

combine_fragments(Fragments) ->
    [Fragment | Rest] = maps:values(Fragments),
    lists:foldl(fun combine_fragments/2, Fragment, Rest).

combine_fragments(Fragment1 = #bctx_v1_ContextFragment{}, Fragment2 = #bctx_v1_ContextFragment{}) ->
    combine_records(Fragment1, Fragment2).

combine_records(Record1, Record2) ->
    [Tag | Fields1] = tuple_to_list(Record1),
    [Tag | Fields2] = tuple_to_list(Record2),
    list_to_tuple([Tag | lists:zipwith(fun combine_fragment_fields/2, Fields1, Fields2)]).

combine_fragment_fields(undefined, V) ->
    V;
combine_fragment_fields(V, undefined) ->
    V;
combine_fragment_fields(V, V) ->
    V;
combine_fragment_fields(V1, V2) when is_tuple(V1), is_tuple(V2) ->
    combine_records(V1, V2);
combine_fragment_fields(V1, V2) when is_list(V1), is_list(V2) ->
    ordsets:union(V1, V2).

mock_woody_client(Services0, SupOrConfig) ->
    mock_woody_client(Services0, SupOrConfig, #{}).

mock_woody_client(Services0, SupOrConfig, CustomUrls) ->
    mock_woody_client(Services0, SupOrConfig, CustomUrls, []).

mock_woody_client(Services0, SupOrConfig, CustomUrls, CustomOpts) ->
    start_woody_client(mock_services(Services0, SupOrConfig, CustomUrls), CustomOpts).

mock_services(Services, ConfigOrSup) ->
    mock_services(Services, ConfigOrSup, #{}).

mock_services(Services, Config, CustomUrls) when is_list(Config) ->
    mock_services(Services, ?config(test_sup, Config), CustomUrls);
mock_services(Services, SupPid, CustomUrls) when is_pid(SupPid) ->
    {ok, IP} = inet:parse_address(?CAPI_IP),
    Names = lists:map(fun get_service_name/1, Services),
    ServerID = {dummy, Names},
    Options = #{
        ip => IP,
        port => 0,
        event_handler => scoper_woody_event_handler,
        handlers => lists:map(fun mock_service_handler/1, Services),
        transport_opts => #{num_acceptors => 1}
    },
    ChildSpec = woody_server:child_spec(ServerID, Options),
    {ok, _Pid} = supervisor:start_child(SupPid, ChildSpec),
    {IP, Port} = woody_server:get_addr(ServerID, Options),
    ServiceUrls = lists:foldl(
        fun(Service, Acc) ->
            ServiceName = get_service_name(Service),
            Acc#{ServiceName => make_url(ServiceName, Port)}
        end,
        #{},
        Services
    ),
    maps:merge(CustomUrls, ServiceUrls).

get_service_name({ServiceName, _Fun}) ->
    ServiceName;
get_service_name({ServiceName, _WoodyService, _Fun}) ->
    ServiceName.

mock_service_handler({ServiceName, Fun}) ->
    mock_service_handler(ServiceName, capi_woody_client:get_service_modname(ServiceName), Fun);
mock_service_handler({ServiceName, WoodyService, Fun}) ->
    mock_service_handler(ServiceName, WoodyService, Fun).

mock_service_handler(ServiceName, WoodyService, Fun) ->
    {make_path(ServiceName), {WoodyService, {capi_dummy_service, #{function => Fun}}}}.

start_woody_client(ServiceURLs, CustomOpts) ->
    capi_ct_helper:start_app(capi_woody_client, [{service_urls, ServiceURLs} | CustomOpts]).

start_bouncer_client(ServiceURLs) ->
    ServiceClients = maps:map(fun(_, URL) -> #{url => URL} end, ServiceURLs),
    Acc = application:get_env(bouncer_client, service_clients, #{}),
    capi_ct_helper:start_app(bouncer_client, [{service_clients, maps:merge(Acc, ServiceClients)}]).

make_url(ServiceName, Port) ->
    iolist_to_binary(["http://", ?CAPI_HOST_NAME, ":", integer_to_list(Port), make_path(ServiceName)]).

make_path(ServiceName) ->
    "/" ++ atom_to_list(ServiceName).

get_context(Token) ->
    capi_client_lib:get_context(?CAPI_URL, Token, 10000, ipv4).

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

get_lifetime() ->
    get_lifetime(0, 0, 7).

get_lifetime(YY, MM, DD) ->
    #{
        <<"years">> => YY,
        <<"months">> => MM,
        <<"days">> => DD
    }.

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).
