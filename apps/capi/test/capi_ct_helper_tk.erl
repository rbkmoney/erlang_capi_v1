-module(capi_ct_helper_tk).

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-define(NS_TOKENKEEPER, <<"com.rbkmoney.token-keeper">>).

-export([default_handler/2]).
-export([mock_handler/2]).

-spec default_handler(Op :: atom(), Args :: tuple()) -> {ok, _} | {error, _}.
default_handler('GetByToken', {Token, _}) ->
    mock_handler(Token, [
        {user, [id, email, realm, orgs]},
        {auth, [{method, <<"SessionToken">>}, expiration, token]}
    ]).

-spec mock_handler(Token :: binary(), Spec :: any()) -> {ok, _} | {error, _}.
mock_handler(Token, Spec) ->
    case capi_authorizer_jwt:verify(Token) of
        {ok, TokenInfo} ->
            {ok, #token_keeper_AuthData{
                token = Token,
                status = active,
                context = encode_context(get_context(TokenInfo, Spec)),
                authority = ?NS_TOKENKEEPER,
                metadata = #{?NS_TOKENKEEPER => get_metadata(TokenInfo)}
            }};
        {error, _} ->
            {error, #token_keeper_AuthDataNotFound{}}
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
    #{id => RealmID};
get_user_fragment_value(orgs, Claims) ->
    UserID = capi_authorizer_jwt:get_subject_id(Claims),
    [
        #{
            id => UserID,
            owner => #{id => UserID},
            party => #{id => UserID}
        }
    ];
get_user_fragment_value({orgs, OrgSpecs}, Claims) ->
    lists:foldl(
        fun(OrgSpec, Acc0) ->
            [assemble_user_orgs_spec(OrgSpec, Claims) | Acc0]
        end,
        [],
        OrgSpecs
    ).

assemble_user_orgs_spec(OrgSpec, Claims) ->
    lists:foldl(
        fun(SpecFragment, Acc0) ->
            FragName = get_user_org_fragment_name(SpecFragment, Claims),
            Acc0#{FragName => get_user_org_fragment_value(SpecFragment, Claims)}
        end,
        #{},
        OrgSpec
    ).

get_user_org_fragment_name(Atom, _Claims) when is_atom(Atom) ->
    Atom;
get_user_org_fragment_name({Atom, _Spec}, _Claims) when is_atom(Atom) ->
    Atom.

get_user_org_fragment_value(id, Claims) ->
    capi_authorizer_jwt:get_subject_id(Claims);
get_user_org_fragment_value({id, ID}, _Claims) ->
    ID;
get_user_org_fragment_value(owner, Claims) ->
    #{id => capi_authorizer_jwt:get_subject_id(Claims)};
get_user_org_fragment_value({owner, OwnerID}, _Claims) ->
    #{id => OwnerID};
get_user_org_fragment_value(party, Claims) ->
    #{id => capi_authorizer_jwt:get_subject_id(Claims)};
get_user_org_fragment_value({party, PartyID}, _Claims) ->
    #{id => PartyID}.

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

get_metadata({Claims, _}) ->
    UserID = capi_authorizer_jwt:get_subject_id(Claims),
    Email = capi_authorizer_jwt:get_subject_email(Claims),
    genlib_map:compact(#{
        <<"party_id">> => UserID,
        <<"user_id">> => UserID,
        <<"user_email">> => Email
    }).

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
