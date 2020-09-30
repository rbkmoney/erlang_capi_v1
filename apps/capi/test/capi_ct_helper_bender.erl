-module(capi_ct_helper_bender).

-include_lib("bender_proto/include/bender_thrift.hrl").

-type tid() :: any().
-type internal_id() :: binary().
-type msg_pack() :: msgpack_thrift:'Value'().

-export([get_result/1]).
-export([get_result/2]).
-export([create_storage/0]).
-export([del_storage/1]).
-export([get_internal_id/3]).

-spec get_result(binary()) -> bender_thrift:bender_GenerationResult().
-spec get_result(binary(), msgpack_thrift:'Value'() | undefined) -> bender_thrift:bender_GenerationResult().

get_result(ID) ->
    get_result(ID, undefined).

get_result(ID, Context) ->
    #bender_GenerationResult{
        internal_id = ID,
        context     = Context
}.

-spec create_storage() -> tid().
-spec del_storage(tid()) -> ok.
-spec get_internal_id(tid(), internal_id(), msg_pack()) -> bender_thrift:bender_GenerationResult().

create_storage() ->
    ets:new(bender_storage, [set, public]).

del_storage(Tid) ->
    ets:delete(Tid).

get_internal_id(Tid, IdempotentKey, MsgPack) ->
    case ets:lookup(Tid, IdempotentKey) of
        [] ->
            ets:insert(Tid, {IdempotentKey, #{
                ctx => MsgPack
            }}),
            {ok, get_result(IdempotentKey)};
        [{IdempotentKey, #{ctx := Ctx}}] ->
            {ok, get_result(IdempotentKey, Ctx)}
    end.

