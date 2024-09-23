BOOLEAN NmiCallback(
    _In_opt_ const PVOID Context,
    _In_ BOOLEAN Handled
)
{
    UNREFERENCED_PARAMETER( Handled );

    const auto NmiContext = static_cast< nt::NMI_CALLBACK_CONTEXT* >( Context );

    const auto Block = &NmiContext[ KeGetCurrentProcessorNumber ( ) ];

    const auto Tss = reinterpret_cast< nt::_KTSS64* >( __readgsqword( 0x8 ) );
    const auto Frame = reinterpret_cast< nt::_MACHINE_FRAME* >( Tss->Ist[ 3 ] - sizeof( nt::_MACHINE_FRAME ) );
    const auto Thread = reinterpret_cast< nt::_ETHREAD* >( KeGetCurrentThread ( ) );

    Block->Rsp = Frame->Rsp;
    Block->Ss = Frame->SegSs;

    Block->Rip = Frame->Rip;
    Block->Cs = Frame->SegCs;

    Block->Flags = Frame->EFlags;

    Block->Dtb = __readcr3 ( );

    Block->Usermode = ( Frame->Rip & 0xFFFF000000000000llu ) == 0;

    Block->ThreadStartAddress = reinterpret_cast< ULONG_PTR >(
        Thread->StartAddress
    );

    /*
     * Besides the obvious risk of us interrupting code in CPL 3, there's a small window inside `KiSystemCall64`:
     *  -----
     *  swapgs
     *  mov qword ptr [gs:0x10], rsp {__return_addr} ; interrupting immediately before or after this instruction means we still have a user-mode stack
     *  mov rsp, qword ptr [gs:0x1a8]
     *  -----
     * Ensure we are only copying kernel thread stacks, and also that we are not crossing any page boundaries as kernel stacks are pageable.
     */
    if ( !Block->Usermode && ( Block->Rsp & 0xFFFF000000000000llu ) != 0 )
    {
        constexpr auto PAGE_MASK = ~( PAGE_SIZE - 1lu );
        const auto RspBoundary = ( ( Block->Rsp + Block->StackCopiedLen ) & PAGE_MASK ) - 8;

        Block->StackCopiedLen = min(
            Block->Rsp - RspBoundary,
            sizeof( Block->Stack )
        );

        memcpy(
            Block->Stack,
            reinterpret_cast< void* >(
                Block->Rsp + Block->StackCopiedLen
            ),
            Block->StackCopiedLen
        );
    }

    InterlockedDecrement( &Pending );

    return TRUE;
}

nt::KLDR_DATA_TABLE_ENTRY *va::FindModuleByRip( const ULONG_PTR Rip, LIST_ENTRY *FirstModule )
{
    auto CurrentEntry = FirstModule;

    do
    {
        const auto AsLdrEntry = reinterpret_cast< nt::KLDR_DATA_TABLE_ENTRY* >( CurrentEntry );

        const auto Start = reinterpret_cast< ULONG_PTR >( AsLdrEntry->DllBase );
        const auto End = Start + AsLdrEntry->SizeOfImage;

        if ( Rip >= Start && Rip <= End )
            return AsLdrEntry;

        CurrentEntry = CurrentEntry->Flink;
    }
    while ( FirstModule != CurrentEntry );

    return nullptr;
}

void va::IssueNmiCallbacks( DEVICE_EXTENSION *Ext )
{
    UNREFERENCED_PARAMETER( Ext );

    const auto CPU_COUNT = KeQueryMaximumProcessorCount ( );

    Pending = static_cast< LONG >( CPU_COUNT );

    VOID *NmiRegHandle = KeRegisterNmiCallback( NmiCallback, Ext->NmiBlock );

    if ( !NmiRegHandle )
    {
        __debugbreak ( );
        return;
    }

    LARGE_INTEGER ThreadSleep = { .QuadPart = -( 100 * 1000 * 10 ) };

    nt::_KAFFINITY_EX Affinity;

    for ( ULONG Proc = 0lu; Proc < CPU_COUNT; Proc++ )
    {
        nt::KeInitializeAffinityEx( &Affinity );
        nt::KeAddProcessorAffinityEx( &Affinity, static_cast< LONG >( Proc ) );

        HalSendNMI( &Affinity );

        KeDelayExecutionThread( KernelMode, false, &ThreadSleep );
    }

    while ( Pending )
        KeDelayExecutionThread( KernelMode, false, &ThreadSleep );

    KeDeregisterNmiCallback( NmiRegHandle );

    for ( auto N = 0lu; N < CPU_COUNT; N++ )
    {
        const auto Data = &Ext->NmiBlock[ N ];

        if ( Data->Usermode )
            continue;

        const auto Module = FindModuleByRip(
            Data->Rip,
            &Ext->SelfLdrEntry->InLoadOrderLinks
        );

        if ( !Module )
        {
            logmsg( "Thread start address: %p @ %p (0x%llx)\n",
                    Data->ThreadStartAddress,
                    Data->Rsp,
                    Data->StackCopiedLen
            );

            constexpr auto STACK_SIZE_IN_QWORDS = sizeof( Data->Stack ) / sizeof( ULONG64 );

            const auto AsPtr = reinterpret_cast< ULONG_PTR* >( Data->Stack );

            for ( auto Index = 0lu; Index < STACK_SIZE_IN_QWORDS; Index++ )
            {
                const auto Value = AsPtr[ Index ];

                // Check if value is canonical. If so, it *might* be a valid address.
                if ( Value & 0xffff000000000000llu && MmIsAddressValid( reinterpret_cast< void* >( Value ) ) )
                {
                    const auto ModuleFromStackAddr = FindModuleByRip(
                        Value,
                        &Ext->SelfLdrEntry->InLoadOrderLinks
                    );

                    if ( !ModuleFromStackAddr )
                    {
                        logmsg( "Address in stack @ %p: %p\n",
                                Data->Stack,
                                Value
                        );

                        continue;
                    }

                    logmsg( "Address in stack @ %p: %p (%wZ+0x%llx)\n",
                            Data->Stack,
                            Value,
                            &ModuleFromStackAddr->BaseDllName,
                            Value - reinterpret_cast< ULONG_PTR >( ModuleFromStackAddr->DllBase )
                    );
                }
            }
        }

        memset( Data, 0, sizeof( *Data ) );

        Ext->NmiExecCounter++;
    }
}