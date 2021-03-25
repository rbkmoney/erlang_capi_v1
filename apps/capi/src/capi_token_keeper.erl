-module(capi_token_keeper).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

%% API functions

-export([get_metadata/2]).
-export([get_bouncer_context/1]).

-export([get_authdata_by_token/2]).

%% API types

-type token() :: binary().
-type token_source_context() :: #{request_origin := binary()}.

-type auth_data() :: tk_token_keeper_thrift:'AuthData'().
-type bouncer_context() :: tk_context_thrift:'ContextFragment'().

-type metadata() :: #{metadata_ns() => #{binary() => binary()}}.
-type metadata_ns() :: binary().

-export_type([token/0]).
-export_type([token_source_context/0]).
-export_type([auth_data/0]).
-export_type([metadata/0]).
-export_type([metadata_ns/0]).

%% Internal types

-type woody_context() :: woody_context:ctx().

%%
%% API functions
%%

-spec get_metadata(metadata_ns(), auth_data()) ->
    metadata().
get_metadata(Namespace, #token_keeper_AuthData{metadata = Metadata}) ->
    maps:get(Namespace, Metadata).

-spec get_bouncer_context(auth_data()) ->
    bouncer_context().
get_bouncer_context(#token_keeper_AuthData{context = Context}) ->
    Context.

-spec get_authdata_by_token(token(), token_source_context() | undefined, woody_context()) ->
    {ok, auth_data()} | {error, _Reason}.
get_authdata_by_token(Token, TokenSource, WoodyContext) ->
    case get_by_token_(Token, encode_token_source(TokenSource), WoodyContext) of
        {ok, #token_keeper_AuthData{context = Context}} ->
            {ok, Context};
        {error, _} = Error ->
            Error
    end.

%%
%% Internal functions
%%

encode_token_source(#{request_origin := Origin}) ->
    #token_keeper_TokenSourceContext{request_origin = Origin};
encode_token_source(undefined) ->
    #token_keeper_TokenSourceContext{}.

get_by_token_(Token, TokenSourceContext, WoodyContext) ->
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
