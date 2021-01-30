-ifndef(capi_dummy_data_included__).
-define(capi_dummy_data_included__, ok).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_webhooker_thrift.hrl").
-include_lib("damsel/include/dmsl_merch_stat_thrift.hrl").
-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").
-include_lib("reporter_proto/include/reporter_reports_thrift.hrl").

-define(BADARG(Term), erlang:binary_to_term(erlang:term_to_binary(Term))).
-define(STRING, <<"TEST">>).
-define(RUB, <<"RUB">>).
-define(USD, <<"USD">>).
-define(BANKID_RU, <<"PUTIN">>).
-define(BANKID_US, <<"TRAMP">>).
-define(JSON, <<"{}">>).
-define(INTEGER, 10000).
-define(INTEGER_BINARY, <<"10000">>).
-define(TIMESTAMP, <<"2016-03-22T06:12:27Z">>).
-define(MD5, <<"033BD94B1168D7E4F0D644C3C95E35BF">>).
-define(SHA256, <<"94EE059335E587E501CC4BF90613E0814F00A7B08BC7C648FD865A2AF6A22CC2">>).

-define(DETAILS, #domain_InvoiceDetails{
    product = ?STRING,
    description = ?STRING
}).

-define(CURRENCY(Code), #domain_CurrencyRef{symbolic_code = Code}).

-define(CASH, #domain_Cash{
    amount = ?INTEGER,
    currency = ?CURRENCY(?RUB)
}).

-define(CASH_FLOW_ACCOUNT_MERCHANT, {merchant, settlement}).
-define(CASH_FLOW_ACCOUNT_PROVIDER, {provider, settlement}).

-define(FINAL_CASH_FLOW, [?FINAL_CASH_FLOW_POSTING]).
-define(FINAL_CASH_FLOW_POSTING, #domain_FinalCashFlowPosting{
    source = ?FINAL_CASH_FLOW_ACCOUNT(?CASH_FLOW_ACCOUNT_MERCHANT),
    destination = ?FINAL_CASH_FLOW_ACCOUNT(?CASH_FLOW_ACCOUNT_PROVIDER),
    volume = ?CASH,
    details = ?STRING
}).

-define(FINAL_CASH_FLOW_ACCOUNT(Type), #domain_FinalCashFlowAccount{
    account_type = Type,
    account_id = ?INTEGER
}).

-define(CONTENT, #'Content'{
    type = <<"application/json">>,
    data = ?JSON
}).

-define(LIFETIME_INTERVAL, #domain_LifetimeInterval{
    years = ?INTEGER,
    months = ?INTEGER,
    days = ?INTEGER
}).

-define(TPL_CASH, {fixed, ?CASH}).

-define(INVOICE_STATUS(Status),
    erlang:apply(
        fun
            (unpaid) ->
                {unpaid, #domain_InvoiceUnpaid{}};
            (paid) ->
                {paid, #domain_InvoicePaid{}};
            (cancelled) ->
                {cancelled, #domain_InvoiceCancelled{details = ?STRING}};
            (fulfilled) ->
                {fulfilled, #domain_InvoiceFulfilled{details = ?STRING}}
        end,
        [Status]
    )
).

-define(INVOICE, #domain_Invoice{
    id = ?STRING,
    created_at = ?TIMESTAMP,
    status = ?INVOICE_STATUS(unpaid),
    due = ?TIMESTAMP,
    details = ?DETAILS,
    cost = ?CASH,
    context = ?CONTENT,
    shop_id = ?STRING,
    owner_id = ?STRING,
    template_id = ?STRING
}).

-define(PAYPROC_INVOICE, ?PAYPROC_INVOICE([])).

-define(PAYPROC_INVOICE(Payments), #payproc_Invoice{
    invoice = ?INVOICE,
    payments = Payments
}).

-define(INVOICE_LINE, #domain_InvoiceLine{
    product = ?STRING,
    quantity = ?INTEGER,
    price = ?CASH,
    metadata = #{?STRING => {obj, #{}}}
}).

-define(INVOICE_TPL, #domain_InvoiceTemplate{
    id = ?STRING,
    details =
        {product, #domain_InvoiceTemplateProduct{
            product = ?STRING,
            price = ?TPL_CASH,
            metadata = #{?STRING => {obj, #{}}}
        }},
    product = ?STRING,
    context = ?CONTENT,
    shop_id = ?STRING,
    owner_id = ?STRING,
    invoice_lifetime = ?LIFETIME_INTERVAL
}).

-define(BANK_CARD, #domain_BankCard{
    token = ?STRING,
    payment_system = visa,
    bin = <<"411111">>,
    last_digits = <<"1111">>
}).

-define(CONTACT_INFO, #domain_ContactInfo{
    phone_number = ?STRING,
    email = <<"test@test.ru">>
}).

-define(DISP_PAYMENT_RESOURCE, #domain_DisposablePaymentResource{
    payment_tool = {bank_card, ?BANK_CARD},
    payment_session_id = ?STRING,
    client_info = #domain_ClientInfo{
        fingerprint = ?STRING,
        ip_address = ?STRING
    }
}).

-define(PAYMENT_RESOURCE_PAYER, #domain_PaymentResourcePayer{
    resource = ?DISP_PAYMENT_RESOURCE,
    contact_info = ?CONTACT_INFO
}).

-define(PAYER, {payment_resource, ?PAYMENT_RESOURCE_PAYER}).

-define(PAYMENT, ?PAYMENT({pending, #domain_InvoicePaymentPending{}})).
-define(PAYMENT(Status), #domain_InvoicePayment{
    id = ?STRING,
    created_at = ?TIMESTAMP,
    domain_revision = ?INTEGER,
    status = Status,
    payer = ?PAYER,
    cost = ?CASH,
    flow = {instant, #domain_InvoicePaymentFlowInstant{}},
    context = ?CONTENT
}).

-define(PAYMENT_PARAMS(ID), #payproc_InvoicePaymentParams{
    id = ID
}).

-define(PAYPROC_PAYMENT(Payment), #payproc_InvoicePayment{
    payment = Payment,
    refunds = [?REFUND],
    legacy_refunds = [?REFUND_DOMAIN],
    adjustments = [?ADJUSTMENT],
    sessions = [
        #payproc_InvoicePaymentSession{
            target_status = {processed, #domain_InvoicePaymentProcessed{}}
        }
    ]
}).

-define(PAYPROC_PAYMENT, ?PAYPROC_PAYMENT(?PAYMENT)).
-define(FAILED_PAYMENT(Failure), ?PAYMENT({failed, #domain_InvoicePaymentFailed{failure = Failure}})).
-define(PAYPROC_FAILED_PAYMENT(Failure), ?PAYPROC_PAYMENT(?FAILED_PAYMENT(Failure))).

-define(ACCOUNT_STATE, #payproc_AccountState{
    account_id = ?INTEGER,
    own_amount = ?INTEGER,
    available_amount = ?INTEGER,
    currency = #domain_Currency{
        name = ?STRING,
        symbolic_code = ?RUB,
        numeric_code = ?INTEGER,
        exponent = ?INTEGER
    }
}).

-define(REFUND, #payproc_InvoicePaymentRefund{
    refund = ?REFUND_DOMAIN,
    sessions = [#payproc_InvoiceRefundSession{}]
}).

-define(REFUND_DOMAIN, ?REFUND_DOMAIN(?STRING)).

-define(REFUND_DOMAIN(ID), #domain_InvoicePaymentRefund{
    id = ID,
    status = {pending, #domain_InvoicePaymentRefundPending{}},
    created_at = ?TIMESTAMP,
    domain_revision = ?INTEGER,
    reason = ?STRING,
    cash = ?CASH
}).

-define(REFUND_PARAMS(ID), #payproc_InvoicePaymentRefundParams{
    id = ID
}).

-define(REFUND_PARAMS(ID, Amount, Currency), #payproc_InvoicePaymentRefundParams{
    id = ID,
    cash = #domain_Cash{amount = Amount, currency = ?CURRENCY(Currency)}
}).

-define(CONTRACT, #domain_Contract{
    id = ?STRING,
    contractor = ?CONTRACTOR,
    payment_institution = #domain_PaymentInstitutionRef{id = ?INTEGER},
    created_at = ?TIMESTAMP,
    valid_since = ?TIMESTAMP,
    valid_until = ?TIMESTAMP,
    status = {active, #domain_ContractActive{}},
    terms = #domain_TermSetHierarchyRef{id = ?INTEGER},
    adjustments = [?CONTRACT_ADJUSTMENT],
    payout_tools = [
        ?PAYOUT_TOOL(?BANKID_RU, ?RUSSIAN_BANK_ACCOUNT),
        ?PAYOUT_TOOL(?BANKID_US, ?INTERNATIONAL_BANK_ACCOUNT)
    ]
}).

-define(CONTRACTOR, {registered_user, #domain_RegisteredUser{email = ?STRING}}).

-define(BLOCKING,
    {unblocked, #domain_Unblocked{
        reason = ?STRING,
        since = ?TIMESTAMP
    }}
).

-define(SUSPENTION, {active, #domain_Active{since = ?TIMESTAMP}}).

-define(SHOP, #domain_Shop{
    id = ?STRING,
    created_at = ?TIMESTAMP,
    blocking = ?BLOCKING,
    suspension = ?SUSPENTION,
    details = ?SHOP_DETAILS,
    location = ?SHOP_LOCATION,
    category = #domain_CategoryRef{id = ?INTEGER},
    contract_id = ?STRING
}).

-define(SHOP_LOCATION, {url, ?STRING}).

-define(SHOP_DETAILS, #domain_ShopDetails{name = ?STRING}).

-define(PARTY_CONTRACTOR, #domain_PartyContractor{
    id = ?STRING,
    contractor =
        {private_entity,
            {russian_private_entity, #domain_RussianPrivateEntity{
                first_name = ?STRING,
                second_name = ?STRING,
                middle_name = ?STRING,
                contact_info = #domain_ContactInfo{}
            }}},
    status = none,
    identity_documents = []
}).

-define(WALLET_CONTRACT_ID, <<"WALLET_CONTRACT_ID">>).

-define(WALLET_CONTRACT, #domain_Contract{
    id = ?WALLET_CONTRACT_ID,
    contractor_id = ?STRING,
    payment_institution = #domain_PaymentInstitutionRef{id = ?INTEGER},
    created_at = ?TIMESTAMP,
    valid_since = ?TIMESTAMP,
    valid_until = ?TIMESTAMP,
    status = {active, #domain_ContractActive{}},
    terms = #domain_TermSetHierarchyRef{id = ?INTEGER},
    adjustments = [],
    payout_tools = []
}).

-define(WALLET, #domain_Wallet{
    id = ?STRING,
    created_at = ?TIMESTAMP,
    blocking = ?BLOCKING,
    suspension = ?SUSPENTION,
    contract = ?WALLET_CONTRACT_ID
}).

-define(LEGAL_AGREEMENT, #domain_LegalAgreement{
    signed_at = ?TIMESTAMP,
    legal_agreement_id = ?STRING,
    valid_until = ?TIMESTAMP
}).

-define(PARTY, #domain_Party{
    id = ?STRING,
    contact_info = #domain_PartyContactInfo{email = ?STRING},
    created_at = ?TIMESTAMP,
    blocking = ?BLOCKING,
    suspension = ?SUSPENTION,
    contracts = #{
        ?STRING => ?CONTRACT,
        ?WALLET_CONTRACT_ID => ?WALLET_CONTRACT
    },
    shops = #{?STRING => ?SHOP},
    contractors = #{?STRING => ?PARTY_CONTRACTOR},
    wallets = #{?STRING => ?WALLET},
    revision = 0
}).

-define(CLAIM(Changeset), #payproc_Claim{
    id = ?INTEGER,
    revision = ?INTEGER,
    created_at = ?TIMESTAMP,
    updated_at = ?TIMESTAMP,
    status = {pending, #payproc_ClaimPending{}},
    changeset = Changeset
}).

-define(CLAIM_CHANGESET, [
    %% contract modifications
    {contract_modification, #payproc_ContractModificationUnit{
        id = ?STRING,
        modification =
            {creation, #payproc_ContractParams{
                contractor = ?CONTRACTOR,
                payment_institution = #domain_PaymentInstitutionRef{id = ?INTEGER}
            }}
    }},
    {contract_modification, #payproc_ContractModificationUnit{
        id = ?STRING,
        modification =
            {termination, #payproc_ContractTermination{
                reason = ?STRING
            }}
    }},
    {contract_modification, #payproc_ContractModificationUnit{
        id = ?STRING,
        modification =
            {adjustment_modification, #payproc_ContractAdjustmentModificationUnit{
                adjustment_id = ?STRING,
                modification =
                    {creation, #payproc_ContractAdjustmentParams{
                        template = #domain_ContractTemplateRef{id = ?INTEGER}
                    }}
            }}
    }},
    {contract_modification, #payproc_ContractModificationUnit{
        id = ?STRING,
        modification =
            {payout_tool_modification, #payproc_PayoutToolModificationUnit{
                payout_tool_id = ?STRING,
                modification =
                    {creation, #payproc_PayoutToolParams{
                        currency = #domain_CurrencyRef{symbolic_code = ?RUB},
                        tool_info = ?RUSSIAN_BANK_ACCOUNT
                    }}
            }}
    }},
    {contract_modification, #payproc_ContractModificationUnit{
        id = ?STRING,
        modification =
            {legal_agreement_binding, ?LEGAL_AGREEMENT}
    }},
    {contract_modification, #payproc_ContractModificationUnit{
        id = ?STRING,
        modification =
            {report_preferences_modification, #domain_ReportPreferences{
                service_acceptance_act_preferences = #domain_ServiceAcceptanceActPreferences{
                    schedule = #domain_BusinessScheduleRef{id = ?INTEGER},
                    signer = #domain_Representative{
                        position = ?STRING,
                        full_name = ?STRING,
                        document = {articles_of_association, #domain_ArticlesOfAssociation{}}
                    }
                }
            }}
    }},
    %% shop modifications
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification =
            {creation, #payproc_ShopParams{
                location = ?SHOP_LOCATION,
                details = ?SHOP_DETAILS,
                contract_id = ?STRING,
                payout_tool_id = ?STRING
            }}
    }},
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification = {category_modification, #domain_CategoryRef{id = ?INTEGER}}
    }},
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification = {details_modification, ?SHOP_DETAILS}
    }},
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification =
            {contract_modification, #payproc_ShopContractModification{
                contract_id = ?STRING,
                payout_tool_id = ?STRING
            }}
    }},
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification = {payout_tool_modification, ?STRING}
    }},
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification = {location_modification, ?SHOP_LOCATION}
    }},
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification =
            {shop_account_creation, #payproc_ShopAccountParams{
                currency = #domain_CurrencyRef{symbolic_code = ?RUB}
            }}
    }},
    {shop_modification, #payproc_ShopModificationUnit{
        id = ?STRING,
        modification =
            {payout_schedule_modification, #payproc_ScheduleModification{
                schedule = #domain_BusinessScheduleRef{id = ?INTEGER}
            }}
    }}
]).

-define(CONTRACTOR_CLAIM_CHANGESET, [
    %% contractor modifications
    {contractor_modification, #payproc_ContractorModificationUnit{
        id = ?STRING,
        modification = {creation, ?CONTRACTOR}
    }},
    {contractor_modification, #payproc_ContractorModificationUnit{
        id = ?STRING,
        modification = {identification_level_modification, partial}
    }},
    {contractor_modification, #payproc_ContractorModificationUnit{
        id = ?STRING,
        modification =
            {identity_documents_modification, #payproc_ContractorIdentityDocumentsModification{
                identity_documents = []
            }}
    }}
]).

-define(WALLET_CLAIM_CHANGESET, [
    %% wallet modifications
    {wallet_modification, #payproc_WalletModificationUnit{
        id = ?STRING,
        modification =
            {creation, #payproc_WalletParams{
                name = ?STRING,
                contract_id = ?WALLET_CONTRACT_ID
            }}
    }}
]).

-define(ADJUSTMENT, #domain_InvoicePaymentAdjustment{
    id = ?STRING,
    status = {pending, #domain_InvoicePaymentAdjustmentPending{}},
    created_at = ?TIMESTAMP,
    domain_revision = ?INTEGER,
    reason = ?STRING,
    new_cash_flow = [],
    old_cash_flow_inverse = []
}).

-define(CONTRACT_ADJUSTMENT, #domain_ContractAdjustment{
    id = ?STRING,
    created_at = ?TIMESTAMP,
    valid_since = ?TIMESTAMP,
    valid_until = ?TIMESTAMP,
    terms = #domain_TermSetHierarchyRef{id = ?INTEGER}
}).

-define(PAYOUT_TOOL(ID, ToolInfo), #domain_PayoutTool{
    id = ID,
    created_at = ?TIMESTAMP,
    currency = #domain_CurrencyRef{symbolic_code = ?RUB},
    payout_tool_info = ToolInfo
}).

-define(RUSSIAN_BANK_ACCOUNT,
    {russian_bank_account, #domain_RussianBankAccount{
        account = <<"12345678901234567890">>,
        bank_name = ?STRING,
        bank_post_account = <<"12345678901234567890">>,
        bank_bik = <<"123456789">>
    }}
).

-define(INTERNATIONAL_BANK_ACCOUNT,
    {international_bank_account, #domain_InternationalBankAccount{
        number = <<"12345678901234567890">>,
        bank = ?INTERNATIONAL_BANK_DETAILS,
        correspondent_account = #domain_InternationalBankAccount{number = <<"00000000000000000000">>},
        iban = <<"GR1601101250000000012300695">>,
        account_holder = ?STRING
    }}
).

-define(INTERNATIONAL_BANK_DETAILS, #domain_InternationalBankDetails{
    %% In reality either bic or aba_rtn should be used, not both.
    bic = <<"DEUTDEFF500">>,
    country = usa,
    name = ?STRING,
    address = ?STRING,
    aba_rtn = <<"129131673">>
}).

-define(WEBHOOK, #webhooker_Webhook{
    id = ?INTEGER,
    party_id = ?STRING,
    event_filter =
        {invoice, #webhooker_InvoiceEventFilter{
            shop_id = ?STRING,
            types = [{created, #webhooker_InvoiceCreated{}}]
        }},
    url = ?STRING,
    pub_key = ?STRING,
    enabled = true
}).

-define(STAT_RESPONSE(Data), #merchstat_StatResponse{
    data = Data
}).

-define(STAT_RESPONSE_INVOICES, ?STAT_RESPONSE({invoices, [?STAT_INVOICE]})).

-define(STAT_RESPONSE_PAYMENTS,
    ?STAT_RESPONSE(
        {payments, [
            ?STAT_PAYMENT(?STAT_PAYER({bank_card, ?STAT_BANK_CARD})),
            ?STAT_PAYMENT(?STAT_PAYER({bank_card, ?STAT_BANK_CARD_WITH_TP}))
        ]}
    )
).

-define(STAT_RESPONSE_RECORDS, ?STAT_RESPONSE({records, [?STAT_RECORD]})).

-define(STAT_RESPONSE_PAYOUTS,
    ?STAT_RESPONSE(
        {payouts, [
            ?STAT_PAYOUT({bank_card, #merchstat_PayoutCard{card = ?STAT_BANK_CARD}}, [?STAT_PAYOUT_SUMMARY_ITEM]),
            ?STAT_PAYOUT({bank_card, #merchstat_PayoutCard{card = ?STAT_BANK_CARD_WITH_TP}}, [?STAT_PAYOUT_SUMMARY_ITEM]),
            ?STAT_PAYOUT({bank_account, ?STAT_PAYOUT_BANK_ACCOUNT_RUS}, undefined),
            ?STAT_PAYOUT({bank_account, ?STAT_PAYOUT_BANK_ACCOUNT_INT}, [?STAT_PAYOUT_SUMMARY_ITEM])
        ]}
    )
).

-define(STAT_INVOICE, #merchstat_StatInvoice{
    id = ?STRING,
    owner_id = ?STRING,
    shop_id = ?STRING,
    created_at = ?TIMESTAMP,
    status = {unpaid, #merchstat_InvoiceUnpaid{}},
    product = ?STRING,
    description = ?STRING,
    due = ?TIMESTAMP,
    amount = ?INTEGER,
    currency_symbolic_code = ?RUB,
    context = ?CONTENT
}).

-define(STAT_PAYMENT(Payer), #merchstat_StatPayment{
    id = ?STRING,
    invoice_id = ?STRING,
    owner_id = ?STRING,
    shop_id = ?STRING,
    created_at = ?TIMESTAMP,
    status = {pending, #merchstat_InvoicePaymentPending{}},
    amount = ?INTEGER,
    flow = {instant, #merchstat_InvoicePaymentFlowInstant{}},
    fee = ?INTEGER,
    currency_symbolic_code = ?RUB,
    payer = Payer,
    context = ?CONTENT,
    domain_revision = ?INTEGER
}).

-define(STAT_PAYER(PaymentTool),
    {payment_resource, #merchstat_PaymentResourcePayer{
        payment_tool = PaymentTool,
        ip_address = ?STRING,
        fingerprint = ?STRING,
        phone_number = ?STRING,
        email = <<"test@test.ru">>,
        session_id = ?STRING
    }}
).

-define(STAT_RECORD, #{
    <<"offset">> => ?INTEGER_BINARY,
    <<"successful_count">> => ?INTEGER_BINARY,
    <<"conversion">> => ?INTEGER_BINARY,
    <<"city_id">> => ?INTEGER_BINARY,
    <<"currency_symbolic_code">> => ?RUB,
    <<"amount_with_fee">> => ?INTEGER_BINARY,
    <<"amount_without_fee">> => ?INTEGER_BINARY,
    <<"unic_count">> => ?INTEGER_BINARY,
    <<"total_count">> => ?INTEGER_BINARY,
    <<"payment_system">> => <<"visa">>
}).

-define(STAT_PAYOUT(Type, PayoutSummary), #merchstat_StatPayout{
    id = ?STRING,
    party_id = ?STRING,
    shop_id = ?STRING,
    created_at = ?TIMESTAMP,
    status = {paid, #merchstat_PayoutPaid{}},
    amount = ?INTEGER,
    fee = ?INTEGER,
    currency_symbolic_code = ?RUB,
    type = Type,
    summary = PayoutSummary
}).

-define(STAT_PAYOUT_BANK_ACCOUNT_RUS,
    {russian_payout_account, #merchstat_RussianPayoutAccount{
        bank_account = #merchstat_RussianBankAccount{
            account = <<"12345678901234567890">>,
            bank_name = ?STRING,
            bank_post_account = <<"12345678901234567890">>,
            bank_bik = <<"123456789">>
        },
        inn = ?STRING,
        purpose = ?STRING
    }}
).

-define(STAT_PAYOUT_BANK_ACCOUNT_INT,
    {international_payout_account, #merchstat_InternationalPayoutAccount{
        bank_account = #merchstat_InternationalBankAccount{
            number = <<"12345678901234567890">>,
            bank = ?STAT_PAYOUT_BANK_DETAILS_INT,
            correspondent_account = #merchstat_InternationalBankAccount{number = <<"00000000000000000000">>},
            iban = <<"GR1601101250000000012300695">>,
            account_holder = ?STRING
        },
        purpose = ?STRING
    }}
).

-define(STAT_PAYOUT_BANK_DETAILS_INT, #merchstat_InternationalBankDetails{
    %% In reality either bic or aba_rtn should be used, not both.
    bic = <<"DEUTDEFF500">>,
    country = usa,
    name = ?STRING,
    address = ?STRING,
    aba_rtn = <<"129131673">>
}).

-define(STAT_BANK_CARD, #merchstat_BankCard{
    token = ?STRING,
    payment_system = visa,
    bin = <<"411111">>,
    masked_pan = <<"1111">>
}).

-define(STAT_BANK_CARD_WITH_TP, #merchstat_BankCard{
    token = ?STRING,
    payment_system = visa,
    bin = <<"411111">>,
    masked_pan = <<"1111">>,
    token_provider = applepay
}).

-define(STAT_PAYOUT_SUMMARY_ITEM, #merchstat_PayoutSummaryItem{
    amount = ?INTEGER,
    fee = ?INTEGER,
    currency_symbolic_code = ?RUB,
    from_time = ?TIMESTAMP,
    to_time = ?TIMESTAMP,
    operation_type = payment,
    count = ?INTEGER
}).

-define(PAYOUT(Type, PayoutSummary), #payout_processing_Payout{
    id = ?STRING,
    party_id = ?STRING,
    shop_id = ?STRING,
    contract_id = ?STRING,
    created_at = ?TIMESTAMP,
    status = {paid, #payout_processing_PayoutPaid{}},
    amount = ?INTEGER,
    fee = ?INTEGER,
    currency = ?CURRENCY(?RUB),
    payout_flow = ?FINAL_CASH_FLOW,
    summary = PayoutSummary,
    type = Type
}).

-define(PAYOUT_SUMMARY_ITEM, #payout_processing_PayoutSummaryItem{
    amount = ?INTEGER,
    fee = ?INTEGER,
    currency_symbolic_code = ?RUB,
    from_time = ?TIMESTAMP,
    to_time = ?TIMESTAMP,
    operation_type = payment,
    count = ?INTEGER
}).

-define(PAYOUT_BANK_ACCOUNT_RUS,
    {bank_account,
        {russian_payout_account, #payout_processing_RussianPayoutAccount{
            bank_account = #domain_RussianBankAccount{
                account = <<"12345678901234567890">>,
                bank_name = ?STRING,
                bank_post_account = <<"12345678901234567890">>,
                bank_bik = <<"123456789">>
            },
            inn = ?STRING,
            purpose = ?STRING,
            legal_agreement = ?LEGAL_AGREEMENT
        }}}
).

-define(REPORT, #reports_Report{
    report_id = ?INTEGER,
    time_range = #reports_ReportTimeRange{
        from_time = ?TIMESTAMP,
        to_time = ?TIMESTAMP
    },
    created_at = ?TIMESTAMP,
    report_type = <<"provision_of_service">>,
    status = created,
    files = [
        #reports_FileMeta{
            file_id = ?STRING,
            filename = ?STRING,
            signature = #reports_Signature{
                md5 = ?MD5,
                sha256 = ?SHA256
            }
        }
    ],
    shop_id = ?STRING,
    party_id = ?STRING
}).

-define(FOUND_REPORTS, #'reports_StatReportResponse'{
    reports = [?REPORT]
}).

-define(GLOBALS,
    {globals, #domain_GlobalsObject{
        ref = #domain_GlobalsRef{},
        data = #domain_Globals{
            external_account_set = {value, #domain_ExternalAccountSetRef{id = ?INTEGER}},
            payment_institutions = [#domain_PaymentInstitutionRef{id = ?INTEGER}],
            contract_payment_institution_defaults = #domain_ContractPaymentInstitutionDefaults{
                test = #domain_PaymentInstitutionRef{id = ?INTEGER},
                live = #domain_PaymentInstitutionRef{id = ?INTEGER}
            }
        }
    }}
).

-define(SNAPSHOT, #'Snapshot'{
    version = ?INTEGER,
    domain = #{
        {globals, #domain_GlobalsRef{}} => ?GLOBALS,
        {category, #domain_CategoryRef{id = ?INTEGER}} =>
            {category, #domain_CategoryObject{
                ref = #domain_CategoryRef{id = ?INTEGER},
                data = #domain_Category{
                    name = ?STRING,
                    description = ?STRING
                }
            }},
        {business_schedule, #domain_BusinessScheduleRef{id = ?INTEGER}} =>
            {business_schedule, #domain_BusinessScheduleObject{
                ref = #domain_BusinessScheduleRef{id = ?INTEGER},
                data = #domain_BusinessSchedule{
                    name = ?STRING,
                    description = ?STRING,
                    schedule = #'Schedule'{
                        year = {every, #'ScheduleEvery'{}},
                        month = {every, #'ScheduleEvery'{}},
                        day_of_month = {every, #'ScheduleEvery'{}},
                        day_of_week = {every, #'ScheduleEvery'{}},
                        hour = {every, #'ScheduleEvery'{}},
                        minute = {every, #'ScheduleEvery'{}},
                        second = {every, #'ScheduleEvery'{}}
                    },
                    delay = #'TimeSpan'{},
                    policy = #domain_PayoutCompilationPolicy{
                        assets_freeze_for = #'TimeSpan'{}
                    }
                }
            }},
        {payment_institution, #domain_PaymentInstitutionRef{id = ?INTEGER}} =>
            {payment_institution, #domain_PaymentInstitutionObject{
                ref = #domain_PaymentInstitutionRef{id = ?INTEGER},
                data = #domain_PaymentInstitution{
                    name = ?STRING,
                    description = ?STRING,
                    system_account_set = {value, #domain_SystemAccountSetRef{id = ?INTEGER}},
                    default_contract_template = {value, #domain_ContractTemplateRef{id = ?INTEGER}},
                    providers = {value, []},
                    inspector = {value, #domain_InspectorRef{id = ?INTEGER}},
                    realm = test,
                    residences = [rus]
                }
            }}
    }
}).

-define(INVOICE_EVENT(ID), #payproc_Event{
    id = ID,
    created_at = ?TIMESTAMP,
    payload =
        {invoice_changes, [
            {invoice_created, #payproc_InvoiceCreated{invoice = ?INVOICE}},
            {invoice_status_changed, #payproc_InvoiceStatusChanged{status = ?INVOICE_STATUS(unpaid)}},
            {invoice_status_changed, #payproc_InvoiceStatusChanged{status = ?INVOICE_STATUS(paid)}},
            {invoice_status_changed, #payproc_InvoiceStatusChanged{status = ?INVOICE_STATUS(cancelled)}},
            {invoice_status_changed, #payproc_InvoiceStatusChanged{status = ?INVOICE_STATUS(fulfilled)}}
        ]},
    source = {invoice_id, ?STRING}
}).

-define(INVOICE_EVENT_PRIVATE(ID), #payproc_Event{
    id = ID,
    created_at = ?TIMESTAMP,
    payload =
        {invoice_changes, [
            {invoice_payment_change, #payproc_InvoicePaymentChange{
                id = <<"1">>,
                payload =
                    {invoice_payment_session_change, #payproc_InvoicePaymentSessionChange{
                        target = {processed, #domain_InvoicePaymentProcessed{}},
                        payload = {session_started, #payproc_SessionStarted{}}
                    }}
            }}
        ]},
    source = {invoice_id, ?STRING}
}).

-define(TERM_SET, #domain_TermSet{
    payouts = ?PAYOUTS_SERVICE_TERMS,
    payments = ?PAYMENTS_SERVICE_TERMS
}).

-define(PAYOUTS_SERVICE_TERMS, #domain_PayoutsServiceTerms{}).

-define(PAYMENTS_SERVICE_TERMS, #domain_PaymentsServiceTerms{
    payment_methods =
        {value,
            ordsets:from_list([
                #domain_PaymentMethodRef{
                    id = {bank_card_deprecated, mastercard}
                },
                #domain_PaymentMethodRef{
                    id = {bank_card_deprecated, visa}
                },
                #domain_PaymentMethodRef{
                    id =
                        {tokenized_bank_card_deprecated, #domain_TokenizedBankCard{
                            payment_system = mastercard,
                            token_provider = applepay
                        }}
                },
                #domain_PaymentMethodRef{
                    id =
                        {tokenized_bank_card_deprecated, #domain_TokenizedBankCard{
                            payment_system = visa,
                            token_provider = applepay
                        }}
                },
                #domain_PaymentMethodRef{
                    id =
                        {bank_card, #domain_BankCardPaymentMethod{
                            payment_system = mastercard,
                            token_provider = applepay,
                            tokenization_method = dpan
                        }}
                },
                #domain_PaymentMethodRef{
                    id =
                        {bank_card, #domain_BankCardPaymentMethod{
                            payment_system = visa,
                            token_provider = applepay,
                            tokenization_method = dpan
                        }}
                },
                #domain_PaymentMethodRef{
                    id =
                        {bank_card, #domain_BankCardPaymentMethod{
                            payment_system = mastercard
                        }}
                },
                #domain_PaymentMethodRef{
                    id =
                        {bank_card, #domain_BankCardPaymentMethod{
                            payment_system = visa
                        }}
                }
            ])}
}).

-define(CUSTOMER, #payproc_Customer{
    id = ?STRING,
    owner_id = ?STRING,
    shop_id = ?STRING,
    status = {ready, #payproc_CustomerReady{}},
    created_at = ?TIMESTAMP,
    bindings = [?CUSTOMER_BINDING],
    contact_info = ?CONTACT_INFO,
    metadata = {obj, #{}}
}).

-define(CUSTOMER_BINDING, #payproc_CustomerBinding{
    id = ?STRING,
    rec_payment_tool_id = ?STRING,
    payment_resource = ?DISP_PAYMENT_RESOURCE,
    status = {succeeded, #payproc_CustomerBindingSucceeded{}}
}).

-define(TEST_PAYMENT_TOKEN, ?TEST_PAYMENT_TOKEN(visa)).

-define(TEST_PAYMENT_TOKEN(PaymentSystem),
    capi_utils:map_to_base64url(#{
        <<"type">> => <<"bank_card">>,
        <<"token">> => ?STRING,
        <<"payment_system">> => atom_to_binary(PaymentSystem, utf8),
        <<"bin">> => <<"411111">>,
        <<"masked_pan">> => <<"1111">>
    })
).

-define(TEST_PAYMENT_SESSION,
    capi_utils:map_to_base64url(#{
        <<"paymentSession">> => ?STRING,
        <<"clientInfo">> => #{
            <<"fingerprint">> => <<"test fingerprint">>,
            <<"ip">> => <<"::ffff:127.0.0.1">>
        }
    })
).

-define(TEST_CAPI_DEPLOYMENT, <<"justkiddingaround">>).
-define(TEST_USER_REALM, <<"external">>).
-define(TEST_RULESET_ID, <<"test/api">>).

-endif.
