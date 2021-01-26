-module(capi_authorizer_jwt).

%%

-export([get_child_spec/1]).
-export([init/1]).

-export([store_key/3]).

-export([issue/1]).
-export([issue/2]).
-export([verify/1]).

%% Claims
-export([get_token_id/1]).
-export([set_token_id/2]).
-export([get_subject_id/1]).
-export([set_subject_id/2]).
-export([get_subject_email/1]).
-export([set_subject_email/2]).
-export([get_expires_at/1]).
-export([set_expires_at/2]).
-export([get_acl/1]).
-export([set_acl/2]).

-export([unique_id/0]).

%%

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("jose/include/jose_jwt.hrl").

-type kid() :: binary().
-type key() :: #jose_jwk{}.
-type token() :: binary().
-type token_id() :: binary().
-type claim() :: jsx:json_term().
-type claims() :: #{binary() => claim()}.
-type subject() :: {subject_id(), capi_acl:t()}.
-type subject_id() :: binary().
-type realm() :: binary().
-type expiration() :: non_neg_integer() | unlimited.
-type auth_method() ::
    user_session_token | api_key_token | detect.

-type metadata() :: #{
    auth_method => auth_method(),
    user_realm => realm()
}.

-export_type([subject/0]).
-export_type([claim/0]).
-export_type([claims/0]).
-export_type([token/0]).
-export_type([expiration/0]).
-export_type([auth_method/0]).
-export_type([metadata/0]).

%%

-type options() :: #{
    %% The set of keys used to sign issued tokens and verify signatures on such
    %% tokens.
    keyset => keyset(),
    %% The name of a key used exclusively to sign any issued token.
    %% If not set any token issue is destined to fail.
    signee => key_name()
}.

-type keyset() :: #{key_name() => key_opts()}.

-type key_name() :: term().
-type key_opts() :: #{
    source := key_source(),
    metadata => metadata()
}.

-type key_source() ::
    {pem_file, file:filename()}.

-spec get_child_spec(options()) -> supervisor:child_spec() | no_return().
get_child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, parse_options(Options)]},
        type => supervisor
    }.

parse_options(Options) ->
    Keyset = maps:get(keyset, Options, #{}),
    _ = is_map(Keyset) orelse exit({invalid_option, keyset, Keyset}),
    _ = genlib_map:foreach(
        fun(KeyName, KeyOpts = #{source := Source}) ->
            Metadata = maps:get(metadata, KeyOpts),
            AuthMethod = maps:get(auth_method, Metadata, undefined),
            UserRealm = maps:get(user_realm, Metadata, <<>>),
            _ =
                is_keysource(Source) orelse
                    exit({invalid_source, KeyName, Source}),
            _ =
                is_auth_method(AuthMethod) orelse
                    exit({invalid_auth_method, KeyName, AuthMethod}),
            _ =
                is_binary(UserRealm) orelse
                    exit({invalid_user_realm, KeyName, AuthMethod})
        end,
        Keyset
    ),
    Signee = maps:find(signee, Options),
    {Keyset, Signee}.

is_keysource({pem_file, Fn}) ->
    is_list(Fn) orelse is_binary(Fn);
is_keysource(_) ->
    false.

is_auth_method(user_session_token) ->
    true;
is_auth_method(api_key_token) ->
    true;
is_auth_method(detect) ->
    true;
is_auth_method(undefined) ->
    true;
is_auth_method(_) ->
    false.

%%

-spec init({keyset(), {ok, key_name()} | error}) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init({Keyset, Signee}) ->
    ok = create_table(),
    KeyInfos = maps:map(fun ensure_store_key/2, Keyset),
    ok = select_signee(Signee, KeyInfos),
    {ok, {#{}, []}}.

ensure_store_key(KeyName, KeyOpts) ->
    Source = maps:get(source, KeyOpts),
    Metadata = maps:get(metadata, KeyOpts, #{}),
    case store_key(KeyName, Source, Metadata) of
        {ok, KeyInfo} ->
            KeyInfo;
        {error, Reason} ->
            _ = logger:error("Error importing key ~p: ~p", [KeyName, Reason]),
            exit({import_error, KeyName, Source, Reason})
    end.

select_signee({ok, Keyname}, KeyInfos) ->
    case maps:find(Keyname, KeyInfos) of
        {ok, #{sign := true}} ->
            set_signee(Keyname);
        {ok, KeyInfo} ->
            _ = logger:error("Error setting signee: signing with ~p is not allowed", [Keyname]),
            exit({invalid_signee, Keyname, KeyInfo});
        error ->
            _ = logger:error("Error setting signee: no key named ~p", [Keyname]),
            exit({nonexstent_signee, Keyname})
    end;
select_signee(error, _KeyInfos) ->
    ok.

%%

-type key_info() :: #{
    kid => kid(),
    sign => boolean(),
    verify => boolean()
}.

-spec store_key(key_name(), {pem_file, file:filename()}, metadata()) ->
    {ok, key_info()} | {error, file:posix() | {unknown_key, _}}.
store_key(KeyName, {pem_file, Filename}, Metadata) ->
    store_key(KeyName, {pem_file, Filename}, Metadata, #{
        kid => fun derive_kid_from_public_key_pem_entry/1
    }).

derive_kid_from_public_key_pem_entry(JWK) ->
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    base64url:encode(crypto:hash(sha256, Data)).

-type store_opts() :: #{
    kid => fun((key()) -> kid())
}.

-spec store_key(key_name(), {pem_file, file:filename()}, metadata(), store_opts()) ->
    {ok, key_info()} | {error, file:posix() | {unknown_key, _}}.
store_key(KeyName, {pem_file, Filename}, Metadata, Opts) ->
    case jose_jwk:from_pem_file(Filename) of
        JWK = #jose_jwk{} ->
            Key = construct_key(derive_kid(JWK, Opts), JWK),
            ok = insert_key(KeyName, Key#{metadata => Metadata}),
            {ok, get_key_info(Key)};
        Error = {error, _} ->
            Error
    end.

get_key_info(#{kid := KID, signer := Signer, verifier := Verifier}) ->
    #{
        kid => KID,
        sign => Signer /= undefined,
        verify => Verifier /= undefined
    }.

derive_kid(JWK, #{kid := DeriveFun}) when is_function(DeriveFun, 1) ->
    DeriveFun(JWK).

construct_key(KID, JWK) ->
    #{
        jwk => JWK,
        kid => KID,
        signer =>
            try
                jose_jwk:signer(JWK)
            catch
                error:_ -> undefined
            end,
        verifier =>
            try
                jose_jwk:verifier(JWK)
            catch
                error:_ -> undefined
            end
    }.

%%

-spec issue(claims()) ->
    {ok, token()}
    | {error, nonexistent_signee}.
issue(Claims) ->
    case get_signee_key() of
        Key = #{} ->
            sign(Key, ensure_token_id(Claims));
        undefined ->
            {error, nonexistent_signee}
    end.

-spec issue(key_name(), claims()) ->
    {ok, token()}
    | {error, {nonexistent_key, key_name()}}
    | {error, {invalid_signee, key_info()}}.
issue(KeyName, Claims) ->
    case get_key_by_name(KeyName) of
        Key = #{signer := #{}} ->
            sign(Key, ensure_token_id(Claims));
        Key = #{signer := undefined} ->
            {error, {invalid_signee, get_key_info(Key)}};
        undefined ->
            {error, {nonexistent_key, KeyName}}
    end.

sign(#{kid := KID, jwk := JWK, signer := #{} = JWS}, Claims) ->
    JWT = jose_jwt:sign(JWK, JWS#{<<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

%%

-spec verify(token()) ->
    {ok, {claims(), metadata()}}
    | {error,
        {invalid_token,
            badarg
            | {badarg, term()}
            | {missing, atom()}}
        | {nonexistent_key, kid()}
        | invalid_operation
        | invalid_signature}.
verify(Token) ->
    try
        {_, ExpandedToken} = jose_jws:expand(Token),
        #{<<"protected">> := ProtectedHeader} = ExpandedToken,
        Header = capi_utils:base64url_to_map(ProtectedHeader),
        Alg = get_alg(Header),
        KID = get_kid(Header),
        verify(KID, Alg, ExpandedToken)
    catch
        %% from get_alg and get_kid
        throw:Reason ->
            {error, Reason};
        %% TODO we're losing error information here, e.g. stacktrace
        error:badarg = Reason ->
            {error, {invalid_token, Reason}};
        error:{badarg, _} = Reason ->
            {error, {invalid_token, Reason}};
        error:Reason ->
            {error, {invalid_token, Reason}}
    end.

verify(KID, Alg, ExpandedToken) ->
    case get_key_by_kid(KID) of
        #{jwk := JWK, verifier := Algs, metadata := Metadata} ->
            _ = lists:member(Alg, Algs) orelse throw(invalid_operation),
            verify_with_key(JWK, ExpandedToken, Metadata);
        undefined ->
            {error, {nonexistent_key, KID}}
    end.

verify_with_key(JWK, ExpandedToken, Metadata) ->
    case jose_jwt:verify(JWK, ExpandedToken) of
        {true, #jose_jwt{fields = Claims}, _JWS} ->
            _ = validate_claims(Claims, get_validators()),
            {ok, {Claims, Metadata}};
        {false, _JWT, _JWS} ->
            {error, invalid_signature}
    end.

validate_claims(Claims, [{Name, Claim, Validator} | Rest]) ->
    _ = Validator(Name, maps:get(Claim, Claims, undefined)),
    validate_claims(Claims, Rest);
validate_claims(Claims, []) ->
    Claims.

get_kid(#{<<"kid">> := KID}) when is_binary(KID) ->
    KID;
get_kid(#{}) ->
    throw({invalid_token, {missing, kid}}).

get_alg(#{<<"alg">> := Alg}) when is_binary(Alg) ->
    Alg;
get_alg(#{}) ->
    throw({invalid_token, {missing, alg}}).

%%

get_validators() ->
    [
        {token_id, <<"jti">>, fun check_presence/2},
        {subject_id, <<"sub">>, fun check_presence/2},
        {expires_at, <<"exp">>, fun check_presence/2}
    ].

check_presence(_, V) when V /= undefined ->
    V;
check_presence(C, undefined) ->
    throw({invalid_token, {missing, C}}).

%%

-define(CLAIM_TOKEN_ID, <<"jti">>).
-define(CLAIM_SUBJECT_ID, <<"sub">>).
-define(CLAIM_SUBJECT_EMAIL, <<"email">>).
-define(CLAIM_EXPIRES_AT, <<"exp">>).
-define(CLAIM_ACCESS, <<"resource_access">>).

-spec get_token_id(claims()) -> token_id().
get_token_id(#{?CLAIM_TOKEN_ID := Value}) ->
    Value.

-spec set_token_id(token_id(), claims()) -> claims().
set_token_id(TokenID, Claims) ->
    false = maps:is_key(?CLAIM_TOKEN_ID, Claims),
    Claims#{?CLAIM_TOKEN_ID => TokenID}.

-spec ensure_token_id(claims()) -> claims().
ensure_token_id(#{?CLAIM_TOKEN_ID := _} = Claims) ->
    Claims;
ensure_token_id(#{} = Claims) ->
    set_token_id(unique_id(), Claims).

-spec get_subject_id(claims()) -> subject_id().
get_subject_id(#{?CLAIM_SUBJECT_ID := Value}) ->
    Value.

-spec set_subject_id(subject_id(), claims()) -> claims().
set_subject_id(SubjectID, Claims) ->
    false = maps:is_key(?CLAIM_SUBJECT_ID, Claims),
    Claims#{?CLAIM_SUBJECT_ID => SubjectID}.

-spec get_subject_email(claims()) -> binary() | undefined.
get_subject_email(Claims) ->
    maps:get(?CLAIM_SUBJECT_EMAIL, Claims, undefined).

-spec set_subject_email(binary(), claims()) -> claims().
set_subject_email(SubjectID, Claims) ->
    false = maps:is_key(?CLAIM_SUBJECT_EMAIL, Claims),
    Claims#{?CLAIM_SUBJECT_EMAIL => SubjectID}.

-spec get_expires_at(claims()) -> expiration().
get_expires_at(Claims) ->
    case maps:get(<<"exp">>, Claims) of
        0 -> unlimited;
        V -> V
    end.

-spec set_expires_at(expiration(), claims()) -> claims().
set_expires_at(ExpiresAt, Claims) ->
    false = maps:is_key(?CLAIM_EXPIRES_AT, Claims),
    case ExpiresAt of
        unlimited -> Claims#{?CLAIM_EXPIRES_AT => 0};
        Timestamp -> Claims#{?CLAIM_EXPIRES_AT => Timestamp}
    end.

-spec get_acl(claims()) -> {ok, capi_acl:t()} | {error, _Reason} | undefined.
get_acl(Claims) ->
    case decode_roles(Claims) of
        Roles when Roles /= undefined ->
            try
                {ok, capi_acl:decode(Roles)}
            catch
                error:{badarg, _} = Reason ->
                    {error, {malformed_acl, Reason}}
            end;
        undefined ->
            undefined
    end.

decode_roles(
    #{
        ?CLAIM_ACCESS := #{
            <<"common-api">> := #{
                <<"roles">> := Roles
            }
        }
    }
) when is_list(Roles) ->
    Roles;
decode_roles(_) ->
    undefined.

-spec set_acl(capi_acl:t(), claims()) -> claims().
set_acl(ACL, Claims) ->
    false = maps:is_key(?CLAIM_ACCESS, Claims),
    encode_roles(capi_acl:encode(ACL), Claims).

encode_roles(Roles, Claims) ->
    Claims#{
        ?CLAIM_ACCESS => #{
            <<"common-api">> => #{
                <<"roles">> => Roles
            }
        }
    }.

-spec unique_id() -> token_id().
unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

%%

insert_key(Keyname, Key = #{kid := KID}) ->
    insert_values(#{
        {keyname, Keyname} => Key,
        {kid, KID} => Key
    }).

get_key_by_name(Keyname) ->
    lookup_value({keyname, Keyname}).

get_key_by_kid(KID) ->
    lookup_value({kid, KID}).

set_signee(Keyname) ->
    insert_values(#{
        signee => {keyname, Keyname}
    }).

get_signee_key() ->
    case lookup_value(signee) of
        {keyname, Keyname} ->
            get_key_by_name(Keyname);
        undefined ->
            undefined
    end.

%%

-define(TABLE, ?MODULE).

create_table() ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]),
    ok.

insert_values(Values) ->
    true = ets:insert(?TABLE, maps:to_list(Values)),
    ok.

lookup_value(Key) ->
    case ets:lookup(?TABLE, Key) of
        [{Key, Value}] ->
            Value;
        [] ->
            undefined
    end.
