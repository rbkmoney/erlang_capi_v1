-module(capi_token_keeper).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% API functions

-export([get_authority/1]).
-export([get_bouncer_context/1]).
-export([get_metadata/1]).
-export([get_metadata/2]).

-export([get_subject_id/1]).
-export([get_subject_email/1]).
-export([is_user_session/1]).

-export([get_authdata_by_token/2]).

%% API types

-type authority() :: binary().

-type token() :: binary().
-type token_source_context() :: #{request_origin := binary()}.

-type auth_data() :: tk_token_keeper_thrift:'AuthData'().
-type token_source_context_encoded() :: tk_token_keeper_thrift:'TokenSourceContext'().
-type bouncer_context() :: tk_context_thrift:'ContextFragment'().

-type metadata() :: #{metadata_ns() => metadata_content()}.
-type metadata_content() :: #{binary() => binary()}.
-type metadata_ns() :: binary().

-export_type([authority/0]).
-export_type([token/0]).
-export_type([token_source_context/0]).
-export_type([auth_data/0]).
-export_type([metadata/0]).
-export_type([metadata_content/0]).
-export_type([metadata_ns/0]).

%%

-define(AUTHORITY_USER_SESSION, <<"com.rbkmoney.keycloak">>).
-define(META_NS_USER_SESSION, <<"com.rbkmoney.keycloak">>).
-define(META_NS_API_KEY, <<"com.rbkmoney.apikeymgmt">>).
-define(META_NS_DETECTOR, <<"com.rbkmoney.token-keeper.detector">>).

-define(USER_SESSION_CLASS, <<"user_session_token">>).
-define(API_KEY_CLASS, <<"phony_api_key">>).

%%
%% API functions
%%

-spec get_authority(auth_data()) -> authority().
get_authority(#token_keeper_AuthData{authority = Authority}) ->
    Authority.

-spec get_bouncer_context(auth_data()) -> {encoded_fragment, bouncer_context()}.
get_bouncer_context(#token_keeper_AuthData{context = Context}) ->
    {encoded_fragment, Context}.

-spec get_metadata(auth_data()) -> metadata().
get_metadata(#token_keeper_AuthData{metadata = Metadata}) ->
    Metadata.

-spec get_metadata(metadata_ns(), auth_data()) -> metadata_content() | undefined.
get_metadata(MetadataNS, #token_keeper_AuthData{metadata = Metadata}) ->
    maps:get(MetadataNS, Metadata, undefined).

%%

-spec get_subject_id(auth_data()) -> binary() | undefined.
get_subject_id(AuthData) ->
    {MetaNS, Key} =
        case is_user_session(AuthData) of
            true -> {get_user_session_meta_namespace(), <<"user_id">>};
            false -> {get_api_key_meta_namespace(), <<"party_id">>}
        end,
    case get_metadata(MetaNS, AuthData) of
        Metadata when Metadata =/= undefined ->
            maps:get(Key, Metadata, undefined);
        undefined ->
            undefined
    end.

-spec get_subject_email(auth_data()) -> binary() | undefined.
get_subject_email(AuthData) ->
    case get_metadata(get_user_session_meta_namespace(), AuthData) of
        Metadata when Metadata =/= undefined ->
            maps:get(<<"user_email">>, Metadata, undefined);
        undefined ->
            undefined
    end.

-spec is_user_session(auth_data()) -> boolean().
is_user_session(AuthData) ->
    UserSessionAuthority = get_user_session_authority_name(),
    case get_authority(AuthData) of
        UserSessionAuthority ->
            assert_detector_meta(AuthData, ?USER_SESSION_CLASS);
        _ ->
            false
    end.

%%

-spec get_authdata_by_token(token(), token_source_context() | undefined) -> {ok, auth_data()} | {error, _Reason}.
get_authdata_by_token(Token, TokenSource) ->
    call_get_by_token(Token, encode_token_source(TokenSource), woody_context:new()).

%%
%% Internal functions
%%

%% @TODO config options maybe?
get_user_session_authority_name() ->
    ?AUTHORITY_USER_SESSION.

get_user_session_meta_namespace() ->
    ?META_NS_USER_SESSION.

get_api_key_meta_namespace() ->
    ?META_NS_API_KEY.

get_detector_meta_namespace() ->
    ?META_NS_DETECTOR.

get_detector_class(AuthData) ->
    case get_metadata(get_detector_meta_namespace(), AuthData) of
        #{<<"class">> := Class} ->
            Class;
        undefined ->
            undefined
    end.

assert_detector_meta(AuthData, TargetClass) ->
    case get_detector_class(AuthData) of
        TargetClass ->
            true;
        undefined ->
            %% We assume here that no detection was performed and we should trust the actual authority id
            true;
        _SomeOtherClass ->
            false
    end.

encode_token_source(#{request_origin := Origin}) ->
    #token_keeper_TokenSourceContext{request_origin = Origin};
encode_token_source(undefined) ->
    #token_keeper_TokenSourceContext{}.

-spec call_get_by_token(token(), token_source_context_encoded(), woody_context:ctx()) ->
    {ok, auth_data()}
    | {error, {token, invalid} | {auth_data, not_found | revoked} | {context, creation_failed}}.
call_get_by_token(Token, TokenSourceContext, WoodyContext) ->
    case capi_woody_client:call_service(token_keeper, 'GetByToken', {Token, TokenSourceContext}, WoodyContext) of
        {ok, AuthData} ->
            {ok, AuthData};
        {exception, #token_keeper_InvalidToken{}} ->
            {error, {token, invalid}};
        {exception, #token_keeper_AuthDataNotFound{}} ->
            {error, {auth_data, not_found}};
        {exception, #token_keeper_AuthDataRevoked{}} ->
            {error, {auth_data, revoked}};
        {exception, #token_keeper_ContextCreationFailed{}} ->
            {error, {context, creation_failed}}
    end.
