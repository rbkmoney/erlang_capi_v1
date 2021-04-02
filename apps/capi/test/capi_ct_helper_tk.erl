-module(capi_ct_helper_tk).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-define(TK_META_NS_KEYCLOAK, <<"com.rbkmoney.keycloak">>).
-define(TK_META_NS_APIKEYMGMT, <<"com.rbkmoney.apikeymgmt">>).

-define(TK_AUTHORITY_KEYCLOAK, <<"com.rbkmoney.keycloak">>).
-define(TK_AUTHORITY_CAPI, <<"com.rbkmoney.capi">>).

-define(TK_META_NS_DETECTOR, <<"com.rbkmoney.token-keeper.detector">>).

-export([not_found_handler/2]).
-export([user_session_handler/2]).
-export([mock_handler/4]).

-spec not_found_handler(Op :: atom(), Args :: tuple()) -> no_return().
not_found_handler('GetByToken', _) ->
    woody_error:raise(business, #token_keeper_AuthDataNotFound{}).

-spec user_session_handler(Op :: atom(), Args :: tuple()) -> {ok, _} | {error, _}.
user_session_handler('GetByToken', {Token, _}) ->
    mock_handler(
        Token,
        ?TK_META_NS_KEYCLOAK,
        [
            {user, [id, email, realm]},
            {auth, [{method, <<"SessionToken">>}, expiration, token]}
        ],
        [user_session_meta, {detector_meta, <<"user_session_token">>}]
    ).

-spec mock_handler(Token :: binary(), Authority :: binary(), ContextSpec :: any(), MetadataSpec :: any()) ->
    {ok, _} | {error, _}.
mock_handler(Token, Authority, ContextSpec, MetadataSpec) ->
    case capi_authorizer_jwt:verify(Token) of
        {ok, TokenInfo} ->
            AuthData = #token_keeper_AuthData{
                token = Token,
                status = active,
                context = encode_context(get_context(TokenInfo, ContextSpec)),
                authority = Authority,
                metadata = get_metadata(TokenInfo, MetadataSpec)
            },
            {ok, AuthData};
        {error, _} ->
            woody_error:raise(business, #token_keeper_AuthDataNotFound{})
    end.

get_context({Claims, _}, Spec) ->
    Acc0 = bouncer_context_helpers:empty(),
    add_by_spec(Acc0, Claims, Spec).

add_by_spec(Acc0, _Claims, []) ->
    Acc0;
add_by_spec(Acc0, Claims, [{user, UserSpec} | Rest]) ->
    add_by_spec(add_user_spec(Acc0, UserSpec, Claims), Claims, Rest);
add_by_spec(Acc0, Claims, [{auth, AuthSpec} | Rest]) ->
    add_by_spec(add_auth_spec(Acc0, AuthSpec, Claims), Claims, Rest).

add_user_spec(Acc0, UserSpec, Claims) ->
    bouncer_context_helpers:add_user(
        assemble_user_fragment(UserSpec, Claims),
        Acc0
    ).

add_auth_spec(Acc0, AuthSpec, Claims) ->
    bouncer_context_helpers:add_auth(
        assemble_auth_fragment(AuthSpec, Claims),
        Acc0
    ).

assemble_user_fragment(UserSpec, Claims) ->
    lists:foldl(
        fun(SpecFragment, Acc0) ->
            FragName = get_user_fragment_name(SpecFragment, Claims),
            Acc0#{FragName => get_user_fragment_value(SpecFragment, Claims)}
        end,
        #{},
        UserSpec
    ).

get_user_fragment_name(Atom, _Claims) when is_atom(Atom) ->
    Atom;
get_user_fragment_name({Atom, _Spec}, _Claims) when is_atom(Atom) ->
    Atom.

get_user_fragment_value(id, Claims) ->
    capi_authorizer_jwt:get_subject_id(Claims);
get_user_fragment_value({id, ID}, _Claims) ->
    ID;
get_user_fragment_value(email, Claims) ->
    capi_authorizer_jwt:get_subject_email(Claims);
get_user_fragment_value({email, Email}, _Claims) ->
    Email;
get_user_fragment_value(realm, _Claims) ->
    #{id => <<"external">>};
get_user_fragment_value({realm, RealmID}, _Claims) ->
    #{id => RealmID}.

assemble_auth_fragment(AuthSpec, Claims) ->
    lists:foldl(
        fun(SpecFragment, Acc0) ->
            FragName = get_auth_fragment_name(SpecFragment, Claims),
            Acc0#{FragName => get_auth_fragment_value(SpecFragment, Claims)}
        end,
        #{},
        AuthSpec
    ).

get_auth_fragment_name(Atom, _Claims) when is_atom(Atom) ->
    Atom;
get_auth_fragment_name({Atom, _Spec}, _Claims) when is_atom(Atom) ->
    Atom.

get_auth_fragment_value(method, _Claims) ->
    <<"SessionToken">>;
get_auth_fragment_value({method, Method}, _Claims) ->
    Method;
get_auth_fragment_value(expiration, Claims) ->
    Expiration = capi_authorizer_jwt:get_expires_at(Claims),
    make_auth_expiration(Expiration);
get_auth_fragment_value({expiration, Expiration}, _Claims) ->
    make_auth_expiration(Expiration);
get_auth_fragment_value(token, Claims) ->
    #{id => capi_authorizer_jwt:get_token_id(Claims)};
get_auth_fragment_value({token, ID}, _Claims) ->
    #{id => ID};
get_auth_fragment_value(scope, Claims) ->
    [#{party => #{id => capi_authorizer_jwt:get_subject_id(Claims)}}];
get_auth_fragment_value({scope, ScopeSpecs}, Claims) ->
    lists:foldl(
        fun(ScopeSpec, Acc0) ->
            [assemble_auth_scope_fragment(ScopeSpec, Claims) | Acc0]
        end,
        [],
        ScopeSpecs
    ).

assemble_auth_scope_fragment(ScopeSpec, Claims) ->
    lists:foldl(
        fun(SpecFragment, Acc0) ->
            FragName = get_auth_scope_fragment_name(SpecFragment, Claims),
            Acc0#{FragName => get_auth_scope_fragment_value(SpecFragment, Claims)}
        end,
        #{},
        ScopeSpec
    ).

get_auth_scope_fragment_name(Atom, _Claims) when is_atom(Atom) ->
    Atom;
get_auth_scope_fragment_name({Atom, _Spec}, _Claims) when is_atom(Atom) ->
    Atom.

get_auth_scope_fragment_value(party, Claims) ->
    #{id => capi_authorizer_jwt:get_subject_id(Claims)};
get_auth_scope_fragment_value({Name, EntityID}, _Claims) when is_atom(Name) ->
    #{id => EntityID}.

get_metadata({Claims, _}, MetadataSpec) ->
    lists:foldl(
        fun(SpecFragment, Acc0) ->
            maps:merge(Acc0, get_metadata_by_spec(SpecFragment, Claims))
        end,
        #{},
        MetadataSpec
    ).

get_metadata_by_spec(user_session_meta, Claims) ->
    #{
        ?TK_META_NS_KEYCLOAK => genlib_map:compact(#{
            <<"user_id">> => capi_authorizer_jwt:get_subject_id(Claims),
            <<"user_email">> => capi_authorizer_jwt:get_subject_email(Claims)
        })
    };
get_metadata_by_spec(api_key_meta, Claims) ->
    #{
        ?TK_META_NS_APIKEYMGMT => #{
            <<"party_id">> => capi_authorizer_jwt:get_subject_id(Claims)
        }
    };
get_metadata_by_spec({detector_meta, Class}, _Claims) ->
    #{
        ?TK_META_NS_DETECTOR => #{<<"class">> => Class}
    }.

encode_context(Context) ->
    #bctx_ContextFragment{
        type = v1_thrift_binary,
        content = encode_context_content(Context)
    }.

encode_context_content(Context) ->
    Type = {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, Context) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.

%% Internal functions

make_auth_expiration(Timestamp) when is_integer(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second);
make_auth_expiration(unlimited) ->
    undefined.
