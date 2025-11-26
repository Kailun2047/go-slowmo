import { ScheduleReason, type ExecuteEvent, type GoparkEvent, type GoreadyEvent, type ScheduleEvent } from '../../proto/slowmo';
import { useBoundStore, type BoundState } from './store';

type SharedSliceTestInput = {
    testName: string;
    previousState: Partial<BoundState>;
    event: ScheduleEvent | ExecuteEvent | GoparkEvent | GoreadyEvent;
    handler: (event: any) => void;
    expectedState: Partial<BoundState>;
};

describe('SharedSlice handle event', () => {
    const handleScheduleEvent = useBoundStore.getState().handleScheduleEvent;
    const handleExecuteEvent = useBoundStore.getState().handleExecuteEvent;
    const handleGoparkEvent = useBoundStore.getState().handleGoparkEvent;
    const handleGoreadyEvent = useBoundStore.getState().handleGoreadyEvent;
    const inputs: SharedSliceTestInput[] = [
        {
            testName: 'M-P binding changes on schedule event (new M created)',
            previousState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: false,
                        p: {
                            id: 0,
                            runq: [],
                        },
                        executing: {
                            id: 1,
                            entryFunc: 'runtime.main',
                        },
                    },
                    {
                        isScheduling: false,
                        p: {
                            id: 1,
                            runq: [],
                        }
                    },
                ],
            },
            event: {
                mId: BigInt(1),
                reason: ScheduleReason.MSTART,
                procId: BigInt(1),
            },
            handler: handleScheduleEvent,
            expectedState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: false,
                        p: {
                            id: 0,
                            runq: [],
                        },
                        executing: {
                            id: 1,
                            entryFunc: 'runtime.main',
                        },
                    },
                    {
                        isScheduling: true,
                        mId: 1,
                        p: {
                            id: 1,
                            runq: [],
                        },
                        executing: undefined,
                    },
                ],
            },
        },
        {
            testName: 'M-P binding changes on schedule event (P transferred between Ms)',
            previousState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: true,
                        p: {
                            id: 0,
                            runq: [
                                {
                                    id: 3,
                                    entryFunc: 'runtime.gcenable.gowrap1'
                                },
                                {
                                    id: 4,
                                    entryFunc: 'runtime.gcenable.gowrap2',
                                },
                            ],
                        },
                        executing: undefined,
                    },
                    {
                        mId: 2,
                        isScheduling: true,
                        p: {
                            id: 1,
                            runq: [],
                        },
                        executing: undefined,
                    },
                ],
            },
            event: {
                mId: BigInt(3),
                reason: ScheduleReason.MSTART,
                procId: BigInt(0),
            },
            handler: handleScheduleEvent,
            expectedState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: true,
                        p: undefined,
                        executing: undefined,
                    },
                    {
                        mId: 2,
                        isScheduling: true,
                        p: {
                            id: 1,
                            runq: [],
                        },
                        executing: undefined,
                    },
                    {
                        mId: 3,
                        isScheduling: true,
                        p: {
                            id: 0,
                            runq: [
                                {
                                    id: 3,
                                    entryFunc: 'runtime.gcenable.gowrap1'
                                },
                                {
                                    id: 4,
                                    entryFunc: 'runtime.gcenable.gowrap2',
                                },
                            ],
                        },
                        executing: undefined,
                    },
                ],
            },
        },
        {
            testName: 'M-P binding changes on execute events (P goes idle)',
            previousState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: true,
                        p: {
                            id: 0,
                            runq: [
                                {
                                    id: 1,
                                    entryFunc: 'runtime.main',
                                },
                            ],
                        },
                        executing: undefined,
                    },
                    {
                        mId: 2,
                        isScheduling: true,
                        p: {
                            id: 1,
                            runq: [],
                            runnext: undefined,
                        },
                        executing: undefined,
                    },
                    {
                        mId: 3,
                        isScheduling: true,
                        p: undefined,
                        executing: undefined,
                    },
                ],
            },
            event: {
                mId: BigInt(2),
                found: {
                    goId: BigInt(1),
                    executionContext: {
                        file: 'proc.go',
                        line: 1,
                        func: 'runtime.main',
                    },
                },
                procId: BigInt(1),
                runqs: [
                    {
                        procId: BigInt(0),
                        runqEntries: [],
                    },
                    {
                        procId: BigInt(1),
                        mId: BigInt(2),
                        runqEntries: [],
                    },
                ],
            },
            handler: handleExecuteEvent,
            expectedState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: true,
                        p: undefined,
                        executing: undefined,
                    },
                    {
                        mId: 2,
                        isScheduling: false,
                        p: {
                            id: 1,
                            runq: [],
                            runnext: undefined,
                        },
                        executing: {
                            id: 1,
                            entryFunc: 'runtime.main',
                        },
                    },
                    {
                        mId: 3,
                        isScheduling: true,
                        p: undefined,
                        executing: undefined,
                    },
                    {
                        mId: undefined,
                        isScheduling: false,
                        p: {
                            id: 0,
                            runq: [],
                            runnext: undefined,
                        },
                    },
                ],
            },
        },
        {
            testName: 'Gopark event',
            previousState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: false,
                        p: {
                            id: 0,
                            runq: [
                                {
                                    id: 8,
                                    entryFunc: 'main.main.func2'
                                },
                                {
                                    id: 9,
                                    entryFunc: 'main.main.func2'
                                },
                                {
                                    id: 10,
                                    entryFunc: 'main.main.func2'
                                },
                            ],
                        },
                        executing: {
                            id: 1,
                            entryFunc: 'runtime.main',
                        },
                    },
                    {
                        mId: 2,
                        isScheduling: false,
                        p: {
                            id: 1,
                            runq: [],
                        },
                        executing: {
                            id: 7,
                            entryFunc: 'main.main.func2',
                        },
                    },
                ],
                parked: [
                    {
                        id: 2,
                        entryFunc: 'runtime.forcegchelper',
                        waitReason: 'force gc (idle)',
                    },
                ],
            },
            event: {
                mId: BigInt(0),
                parked: {
                    goId: BigInt(1),
                    executionContext: {
                        file: 'proc.go',
                        line: 1,
                        func: 'runtime.main',
                    },
                },
                waitReason: 'sync.WaitGroup.Wait',
            },
            handler: handleGoparkEvent,
            expectedState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: false,
                        p: {
                            id: 0,
                            runq: [
                                {
                                    id: 8,
                                    entryFunc: 'main.main.func2'
                                },
                                {
                                    id: 9,
                                    entryFunc: 'main.main.func2'
                                },
                                {
                                    id: 10,
                                    entryFunc: 'main.main.func2'
                                },
                            ],
                        },
                        executing: undefined,
                    },
                    {
                        mId: 2,
                        isScheduling: false,
                        p: {
                            id: 1,
                            runq: [],
                        },
                        executing: {
                            id: 7,
                            entryFunc: 'main.main.func2',
                        },
                    },
                ],
                parked: [
                    {
                        id: 2,
                        entryFunc: 'runtime.forcegchelper',
                        waitReason: 'force gc (idle)',
                    },
                    {
                        id: 1,
                        entryFunc: 'runtime.main',
                        waitReason: 'sync.WaitGroup.Wait',
                    },
                ],
            },
        },
        {
            testName: 'Goready event',
            previousState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: false,
                        p: {
                            id: 0,
                            runq: [],
                        },
                        executing: {
                            id: 9,
                            entryFunc: 'main.main.func2',
                        },
                    },
                    {
                        mId: 2,
                        isScheduling: true,
                        p: {
                            id: 1,
                            runq: [],
                        },
                    },
                ],
                parked: [
                    {
                        id: 2,
                        entryFunc: 'runtime.forcegchelper',
                        waitReason: 'force gc (idle)',
                    },
                    {
                        id: 1,
                        entryFunc: 'runtime.main',
                        waitReason: 'sync.WaitGroup.Wait',
                    },
                ],
            },
            event: {
                mId: BigInt(0),
                goId: BigInt(1),
                runq: {
                    procId: BigInt(0),
                    runqEntries: [
                        {
                            goId: BigInt(1),
                            executionContext: {
                                file: 'proc.go',
                                line: 1,
                                func: 'runtime.main',
                            },
                        },
                    ],
                    mId: BigInt(0),
                    runnext: undefined,
                },
            },
            handler: handleGoreadyEvent,
            expectedState: {
                threads: [
                    {
                        mId: 0,
                        isScheduling: false,
                        p: {
                            id: 0,
                            runq: [
                                {
                                    id: 1,
                                    entryFunc: 'runtime.main',
                                },
                            ],
                            runnext: undefined,
                        },
                        executing: {
                            id: 9,
                            entryFunc: 'main.main.func2',
                        },
                    },
                    {
                        mId: 2,
                        isScheduling: true,
                        p: {
                            id: 1,
                            runq: [],
                        },
                    },
                ],
                parked: [
                    {
                        id: 2,
                        entryFunc: 'runtime.forcegchelper',
                        waitReason: 'force gc (idle)',
                    },
                ],
            },
        },
    ];
    
    test.each(inputs)('$testName', ({previousState, event, handler, expectedState}) => {
        useBoundStore.setState(previousState);
        handler(event);
        const actualState = useBoundStore.getState();
        for (const [key, value] of Object.entries(expectedState)) {
            const actualValue = (actualState as any)[key];
            assert.deepEqual(actualValue, value, `Mismatch in state property '${key}'`);
        }
    })
})