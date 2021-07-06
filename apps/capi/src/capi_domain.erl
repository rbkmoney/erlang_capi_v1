-module(capi_domain).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").

-export([get_payment_institutions/1]).
-export([get_default_payment_institution_ref/2]).
-export([get/2]).
-export([get_objects_by_type/2]).

-type context() :: woody_context:ctx().
-type ref() :: dmsl_domain_thrift:'Reference'().
-type data() :: _.

-type payment_institution() :: #domain_PaymentInstitutionObject{}.
-type payment_institution_ref() :: dmsl_domain_thrift:'PaymentInstitutionRef'().
-type payment_institution_realm() :: dmsl_domain_thrift:'PaymentInstitutionRealm'().

-spec get_payment_institutions(context()) -> {ok, [payment_institution()]}.
get_payment_institutions(Context) ->
    Opts = #{woody_context => Context},

    #'VersionedObject'{
        version = Version,
        object = {globals, #domain_GlobalsObject{data = Globals}}
    } = dmt_client:checkout_versioned_object(latest, globals(), Opts),

    PaymentInstitutionRefs =
        case Globals#domain_Globals.payment_institutions of
            undefined -> [];
            List -> List
        end,

    PaymentInstitutions =
        lists:map(
            fun(Ref) ->
                {payment_institution, Object} = dmt_client:checkout_object(Version, {payment_institution, Ref}, Opts),
                Object
            end,
            PaymentInstitutionRefs
        ),

    {ok, PaymentInstitutions}.

-spec get_default_payment_institution_ref(payment_institution_realm(), context()) -> payment_institution_ref().
get_default_payment_institution_ref(Realm, Context) ->
    #domain_Globals{
        contract_payment_institution_defaults = PaymentInstitutionDefaults
    } = checkout_globals(Context),
    case Realm of
        test ->
            PaymentInstitutionDefaults#domain_ContractPaymentInstitutionDefaults.test;
        live ->
            PaymentInstitutionDefaults#domain_ContractPaymentInstitutionDefaults.live
    end.

-spec get(ref(), context()) -> {ok, data()} | {error, not_found}.
get(Ref, Context) ->
    try
        {_Type, Object} = dmt_client:checkout_object(latest, Ref, #{woody_context => Context}),
        {ok, Object}
    catch
        throw:#'ObjectNotFound'{} ->
            {error, not_found}
    end.

checkout_globals(_Context) ->
    {globals, #domain_GlobalsObject{data = Globals}} = dmt_client:checkout_object(globals()),
    Globals.

globals() ->
    {globals, #domain_GlobalsRef{}}.

-spec get_objects_by_type(Type :: atom(), context()) -> {ok, [tuple()]}.
get_objects_by_type(Type, Context) ->
    Objects = dmt_client:checkout_objects_by_type(latest, Type, #{woody_context => Context}),
    {ok, Objects}.
