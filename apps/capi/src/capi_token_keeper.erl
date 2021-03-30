-module(capi_token_keeper).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% API functions

-export([get_authority/1]).
-export([get_bouncer_context/1]).
-export([get_metadata/1]).

-export([get_subject_id/1]).
-export([get_subject_email/1]).
-export([is_user_access/1]).

-export([get_authdata_by_token/2]).

%% API types

-type authority() :: binary().

-type token() :: binary().
-type token_source_context() :: #{request_origin := binary()}.

-type auth_data() :: tk_token_keeper_thrift:'AuthData'().
-type token_source_context_encoded() :: tk_token_keeper_thrift:'TokenSourceContext'().
-type bouncer_context() :: tk_context_thrift:'ContextFragment'().

-type metadata() :: #{metadata_ns() => #{binary() => binary()}}.
-type metadata_ns() :: binary().

-export_type([authority/0]).
-export_type([token/0]).
-export_type([token_source_context/0]).
-export_type([auth_data/0]).
-export_type([metadata/0]).
-export_type([metadata_ns/0]).

%%

-define(NS_TOKENKEEPER, <<"com.rbkmoney.token-keeper">>).
-define(NS_KEYCLOAK, <<"com.rbkmoney.keycloak">>).

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
    maps:get(?NS_TOKENKEEPER, Metadata, #{}).

%%

-spec get_subject_id(auth_data()) -> binary() | undefined.
get_subject_id(AuthData) ->
    maps:get(<<"user_id">>, get_metadata(AuthData), undefined).

-spec get_subject_email(auth_data()) -> binary() | undefined.
get_subject_email(AuthData) ->
    maps:get(<<"user_email">>, get_metadata(AuthData), undefined).

-spec is_user_access(auth_data()) -> boolean().
is_user_access(AuthData) ->
    case get_authority(AuthData) of
        ?NS_KEYCLOAK ->
            true;
        ?NS_TOKENKEEPER ->
            false
    end.

%%

-spec get_authdata_by_token(token(), token_source_context() | undefined) -> {ok, auth_data()} | {error, _Reason}.
get_authdata_by_token(Token, TokenSource) ->
    call_get_by_token(Token, encode_token_source(TokenSource), woody_context:new()).

%%
%% Internal functions
%%

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
