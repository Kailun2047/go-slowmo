import { create as actualCreate, type StateCreator } from "zustand";
import { ExecuteEvent, GoparkEvent, GoreadyEvent, NewProcEvent, RunqStatusEvent, ScheduleEvent } from "../../proto/slowmo";
import { pickPastelColor, type HSL } from "../lib/color-picker";
import {isNil} from 'lodash';

interface AceEditorWrapperState {
    codeLines: string[];
    setCodeLines: (codeLines: string[]) => void;
}

export const useAceEditorWrapperStore = actualCreate<AceEditorWrapperState>((set) => ({
    codeLines: ['// Your Go code'],
    setCodeLines: (codeLines: string[]) => set(() => ({codeLines})),
}));

const resetStoreFns = new Set<() => void>();
export const resetAllStores = () => {
    for (const fn of resetStoreFns) {
        fn();
    }
}
const create = (<T>() => {
  return (stateCreator: StateCreator<T>) => {
    const store = actualCreate(stateCreator)
    resetStoreFns.add(() => {
      store.setState(store.getInitialState(), true)
    })
    return store
  }
}) as typeof actualCreate

interface RunningCodeLinePerThread {
    lineNumber: number;
    goId: number;
    backgroundColor: HSL;
}

interface CodePanelSlice {
    isRequested: {isRunning: boolean} | undefined;
    runningCodeLines: Map<number, RunningCodeLinePerThread>;
    setIsRequested: (isRequested: {isRunning: boolean}) => void;
    handleDelayEvent: (mId: number, lineNumber: number, goId: number) => void;
}

// Thread is the hybrid of M and its associated P (if any). When mId is
// undefined, it represents the state where P is created but not yet bounded to
// an M. When mId has a value but p is undefined, it represents the state where
// the P originally bounded to this M has been scheduled away to another M. When
// both mId and p have values, it represents the normal state where M is running
// with its bounded P.
export interface Thread {
    mId?: number; // mId is undefined when the thread is not yet started by mstart (in such case there's no drawing for m structure)
    isScheduling: boolean;
    p?: Proc;
    executing?: Goroutine;
}

interface Proc {
    id: number;
    runnext?: Goroutine;
    runq: Goroutine[];
}

interface Goroutine {
    id: number;
    entryFunc: string;
}

interface ThreadsSlice {
    threads: Thread[];
    initThreads: (gomaxprocs: number) => void;
    handleNewProcEvent: (event: NewProcEvent) => void;
}

interface ParkedGoroutine extends Goroutine {
    waitReason: string;
}

interface GlobalStructsSlice {
    parked: ParkedGoroutine[];
}

export enum OutputType {
    Requesting,
    RequestError,
    CompilationError,
    ProgramExited,
}

type Output = {
    type: OutputType.Requesting,
} | {
    type: OutputType.RequestError,
    requestError: string,
} | {
    type: OutputType.CompilationError,
    compilationError: string,
} | {
    type: OutputType.ProgramExited | undefined,
    runtimeOutput: string | undefined,
}

interface OutputState {
    output: Output | undefined;
    outputRequesting: () => void;
    outputRequestError: (requestError: string) => void;
    outputCompilatioError: (compilationError: string) => void;
    outputProgramStart: () => void;
    outputRuntimeOutput: (runtimeOutput: string) => void;
    outputProgramExit: () => void;
}

export const useOutputStore = actualCreate<OutputState>((set, get) => ({
    output: undefined,

    outputRequesting: () => {
        set(() => ({
            output: {type: OutputType.Requesting},
        }));
    },

    outputRequestError: (requestError: string) => {
        set(() => ({
            output: {type: OutputType.RequestError, requestError},
        }));
    },

    outputCompilatioError: (compilationError: string) => {
        set(() => ({
            output: {
                type: OutputType.CompilationError,
                compilationError,
            },
        }));
    },

    outputProgramStart: () => {
        set(() => ({
            output: {type: undefined, runtimeOutput: undefined},
        }))
    },

    outputRuntimeOutput: (runtimeOutput: string) => {
        const oldOut = get().output;
        if (isNil(oldOut) || !isNil(oldOut?.type) && oldOut?.type !== OutputType.Requesting) {
            throw new Error(`received runtime output under invalid output type ${oldOut?.type}`);
        }
        if (oldOut.type === undefined) {
            set(() => ({
                output: {type: undefined, runtimeOutput: (oldOut.runtimeOutput?? '') + runtimeOutput},
            }));
        } else {
            set(() => ({
                output: {type: undefined, runtimeOutput},
            }));
        }
    },

    outputProgramExit: () => {
        const oldOut = get().output;
        if (isNil(oldOut) || !isNil(oldOut?.type)) {
            throw new Error(`program terminated under invalid output type ${oldOut?.type}`);
        }
        set(() => ({
            output: {type: OutputType.ProgramExited, runtimeOutput: oldOut.runtimeOutput}
        }));
    },
}))

interface SharedSlice {
    handleScheduleEvent: (event: ScheduleEvent) => void;
    handleExecuteEvent: (event: ExecuteEvent) => void;
    handleRunqStatusEvent: (event: RunqStatusEvent) => void;
    handleGoparkEvent: (event: GoparkEvent) => void;
    handleGoreadyEvent: (event: GoreadyEvent) => void;
    // updateStructures is used to render local/global structure state changes
    // for an individual event.
    updateStructures: (collectedStructures: Structure[]) => void;
}

export enum StructureType {
    LocalRunq,
    GlobalRunq,
    // Semtable,
    Executing = 3,
    Parked,
};

type Structure = {
    mId: number;
    structureType: StructureType.Executing;
    value?: Goroutine;
} | {
    mId: number | undefined;
    structureType: StructureType.LocalRunq;
    value: Proc;
} | {
    mId: undefined;
    structureType: StructureType.Parked;
    value: ParkedChange;
}

interface ParkedChange {
    added?: ParkedGoroutine;
    removed?: Pick<Goroutine, 'id'>;
}

const createCodePanelSlice: StateCreator<
    CodePanelSlice, [], [], CodePanelSlice
> = (set, get) => ({
    isRequested: undefined,
    runningCodeLines: new Map(),
    setIsRequested: (isRequested: {isRunning: boolean}) => set(() => ({isRequested})),
    handleDelayEvent: (mId: number, lineNumber: number, goId: number) => {
        const runningCodeLines = get().runningCodeLines;
        const runningCodeLinesPerThread = runningCodeLines.get(Number(mId));
        if (!runningCodeLinesPerThread) {
            runningCodeLines.set(Number(mId), {
                lineNumber: lineNumber,
                backgroundColor: pickPastelColor(Number(goId)),
                goId: Number(goId),
            });
        } else {
            runningCodeLinesPerThread.lineNumber = lineNumber;
        }
        set(() => ({
            runningCodeLines: new Map(runningCodeLines),
        }));
    },
})

const createThreadsSlice: StateCreator<
    ThreadsSlice, [], [], ThreadsSlice
> = (set) => ({
    threads: [],

    // initThreads is called once upon receiving num_cpu from server.
    initThreads: (gomaxprocs: number) => {
        const threads: Thread[] = [];
        for (let i = 0; i < gomaxprocs; i++) {
            threads.push(i === 0? {
                mId: i, // p0 is bound to m0 at start
                isScheduling: false,
                p: {
                    id: i,
                    runq: [],
                },
                // m0 executes G0 (rt0_go bootstrap) at start
                executing: {
                    id: 0,
                    entryFunc: '',
                },
            }: {
                isScheduling: false,
                p: {
                    id: i,
                    runq: [],
                }
            })
        }
        set(() => ({
            threads,
        }))
    },

    handleNewProcEvent: (event: NewProcEvent) => {
        const {mId, creatorGoId} = event;
        console.debug(`newProcEvent by goId ${Number(creatorGoId)} on mId ${Number(mId)}`);
    },
})

const createGlobalStructsThread: StateCreator<GlobalStructsSlice, [], []> = () => ({
    parked: [],
})

const createSharedSlice: StateCreator<
    CodePanelSlice & ThreadsSlice & SharedSlice & GlobalStructsSlice, [], [], SharedSlice
> = (set, get) => ({
    handleScheduleEvent: (event: ScheduleEvent) => {
        let {procId: rawProcId, mId: rawMId} = event;
        if (rawProcId === undefined) {
            throw new Error('unexpected new M without procId');
        }
        const mId = Number(rawMId), procId = Number(rawProcId);

        let threads = get().threads;
        threads = checkAndApplyMPBindingChange(threads, mId, procId);

        set((state) => ({
            threads: [...threads.map((thread) => thread.mId === mId? {...thread, executing: undefined, isScheduling: true}: thread)],
            runningCodeLines: new Map([...state.runningCodeLines].filter(([k, _]) => k !== mId)),
        }));
    },

    handleExecuteEvent: (event: ExecuteEvent) => {
        const {found, procId: rawProcId, mId: rawMid, runqs} = event;
        if (found === undefined || found.goId === undefined || found.executionContext?.func === undefined || rawProcId === undefined) {
            throw new Error(`invalid executeEvent`);
        }
        const mId = Number(rawMid);
        let threads = get().threads;
        threads = threads.map((thread) => thread.mId === mId? {...thread, isScheduling: false}: thread);
        set(() => ({
            threads: [...threads],
        }))

        const {goId, executionContext} = found;
        const {func} = executionContext;
        const runqStructs: Structure[] = [];

        runqs.map(runqEvent => {
            const converted = convertRunqStatusEvent(runqEvent);
            runqStructs.push({
                mId: converted.mId,
                structureType: StructureType.LocalRunq,
                value: converted.proc,
            });
        })
        get().updateStructures([
            {
                mId,
                structureType: StructureType.Executing,
                value: {id: Number(goId), entryFunc: func!},
            },
            ...runqStructs,
        ]);
    },

    handleRunqStatusEvent: (event: RunqStatusEvent) => {
        const {mId, proc} = convertRunqStatusEvent(event);
        get().updateStructures([
            {
                mId,
                structureType: StructureType.LocalRunq,
                value: proc,
            },
        ]);
    },

    handleGoparkEvent: (event: GoparkEvent) => {
        if (event.mId === undefined || event.parked === undefined || event.parked.goId === undefined || event.parked.executionContext === undefined || event.waitReason === undefined) {
            throw new Error(`invalid gopark event from mId ${event.mId} with wait reason ${event.waitReason}`)
        }
        const mId = Number(event.mId);
        const {goId, executionContext} = event.parked;
        get().updateStructures([
            {
                mId: mId,
                structureType: StructureType.Executing,
                value: undefined,
            },
            {
                mId: undefined,
                structureType: StructureType.Parked,
                value: {added: {id: Number(goId), entryFunc: executionContext.func?? '', waitReason: event.waitReason}},
            },
        ]);
    },

    handleGoreadyEvent: (event: GoreadyEvent) => {
        const {goId, runq} = event;
        if (goId === undefined || runq === undefined || runq.mId === undefined || runq.procId === undefined) {
            throw new Error(`invalid goready event from mId ${runq?.mId} and goId ${goId}`);
        }
        const {mId, proc} = convertRunqStatusEvent(runq);
        get().updateStructures([
            {
                mId,
                structureType: StructureType.LocalRunq,
                value: proc,
            },
            {
                mId: undefined,
                structureType: StructureType.Parked,
                value: {removed: {id: Number(goId)}},
            },
        ]);
    },

    updateStructures: (structs: Structure[]) => {
        let updatedState: Partial<ThreadsSlice & GlobalStructsSlice> = {};

        let {threads, parked} = get();
        const updatedTypes = new Set<StructureType>();
        for (const struct of structs) {
            const {mId, structureType, value} = struct;
            updatedTypes.add(structureType)
            switch (structureType) {
                case StructureType.Executing: {
                    const thread = threads.find((thread) => thread.mId === mId)
                    if (isNil(thread)) {
                        throw new Error(`thread with mId ${mId} has executing structure change but is not found in thread list`);
                    }
                    thread.executing = value;
                    break;
                }
                case StructureType.LocalRunq: {
                    threads = checkAndApplyMPBindingChange(threads, mId, value.id, value);
                    break;
                }
                case StructureType.Parked: {
                    const {added, removed} = struct.value;
                    if (!isNil(added)) {
                        parked = [...parked, added];
                    }
                    if (!isNil(removed)) {
                       parked = parked.filter(parkedG => parkedG.id !== removed.id);
                    }
                    break;
                }
                default:
                    console.warn(`state change for m${mId} and structure type ${structureType} not applied`);
            }
        }

        if (updatedTypes.has(StructureType.LocalRunq) || updatedTypes.has(StructureType.Executing)) {
            updatedState.threads = [...threads];
        }
        if (updatedTypes.has(StructureType.Parked)) {
            updatedState.parked = [...parked];
        }
        set(() => (updatedState));
    },
})

function convertRunqStatusEvent(event: RunqStatusEvent): {proc: Proc, mId?: number} {
    const {procId, runnext, runqEntries, mId} = event;
    if (procId === undefined) {
        throw new Error(`invalid runqStatusEvent (procId: ${procId}, mId: ${mId})`);
    }
    return {
        proc: {
            id: Number(procId),
            runnext: runnext !== undefined? {
                id: Number(runnext.goId),
                entryFunc: runnext.executionContext?.func?? '',
            }: undefined,
            runq: runqEntries.map(entry => ({
                id: Number(entry.goId),
                entryFunc: entry.executionContext?.func?? '',
            }))
        },
        mId: !isNil(mId)? Number(mId): undefined,
    };
}

// checkAndApplyMPBindingChange checks for possible change in m-p bindings.
function checkAndApplyMPBindingChange(threads: Thread[], mId: number | undefined, procId: number, newP: Proc | undefined = undefined): Thread[] {
    const existingThread = threads.find((thread) => thread.p?.id === procId);
    if (existingThread === undefined) {
        throw new Error(`no existing thread found for procId ${procId}`);
    }

    let targetThread = undefined;
    if (!isNil(mId)) {
        targetThread = threads.find(thread => thread.mId === mId);
    }
    if (targetThread === undefined) {
        targetThread = {mId, isScheduling: false};
        threads = [...threads, targetThread];
    }
    const p = newP?? existingThread.p;
    existingThread.p = undefined;
    const oldP = targetThread.p;
    targetThread.p = p;
    threads = [...threads, {p: oldP, isScheduling: false}];
    return threads.filter(thread => thread.mId !== undefined || thread.p !== undefined);
}

export const useBoundStore = create<CodePanelSlice & ThreadsSlice & GlobalStructsSlice & SharedSlice>()(
    (...args) => ({
        ...createCodePanelSlice(...args),
        ...createThreadsSlice(...args),
        ...createGlobalStructsThread(...args),
        ...createSharedSlice(...args),
    })
);