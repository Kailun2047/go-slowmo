import { create as actualCreate, type StateCreator } from "zustand";
import { ExecuteEvent, NewProcEvent, RunqStatusEvent, ScheduleEvent } from "../../proto/slowmo";
import { pickPastelColor, type HSL } from "../lib/color-picker";

interface AceEditorWrapperState {
    codeLines: string[];
    setCodeLines: (codeLines: string[]) => void;
}

export const useAceEditorWrapperStore = actualCreate<AceEditorWrapperState>((set) => ({
    codeLines: ['// Your Go code'],
    setCodeLines: (codeLines: string[]) => set({codeLines}),
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
    isRunning: boolean;
    runningCodeLines: Map<number, RunningCodeLinePerThread>;
    setIsRunning: (isRunning: boolean) => void;
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

interface SharedSlice {
    handleScheduleEvent: (event: ScheduleEvent) => void;
    handleExecuteEvent: (event: ExecuteEvent) => void;
    handleRunqStatusEvent: (event: RunqStatusEvent) => void;
    // updateStructures is to be invoked upon complete collection of
    // all structure states for a notification event to reflect changed
    // structures in components.
    updateStructures: (collectedStructures: Structure[]) => void;
}

export enum StructureType {
    LocalRunq,
    GlobalRunq,
    Semtable,
    Executing,
};

// An undefined value field means the target structure state has not yet been
// received from structure state event.
type Structure = {
    mId: number;
} & ({
    structureType: StructureType.Executing;
    value?: Goroutine;
} | {
    structureType: StructureType.LocalRunq;
    value?: Proc;
})

const createCodePanelSlice: StateCreator<
    CodePanelSlice & ThreadsSlice, [], [], CodePanelSlice
> = (set, get) => ({
    isRunning: false,
    runningCodeLines: new Map(),
    setIsRunning: (isRunning: boolean) => set({isRunning}),
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
    CodePanelSlice & ThreadsSlice, [], [], ThreadsSlice
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

const createSharedSlice: StateCreator<
    CodePanelSlice & ThreadsSlice & SharedSlice, [], [], SharedSlice
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
            const {mId: runqMId, procId, runnext, runqEntries} = runqEvent;
            if (procId === undefined) {
                throw new Error(`Found invalid runq (procId: ${runqEvent.procId}, mId: ${runqEvent.mId}) in execute event for mId ${mId}`);
            }
            if (runqMId === undefined) {
                console.debug(`Found idle p (procId: ${procId}, mId: ${runqMId}) in execute event for mId ${mId}`);
                return;
            }
            runqStructs.push({
                mId: Number(runqMId),
                structureType: StructureType.LocalRunq,
                value: {
                    id: Number(procId),
                    runnext: runnext !== undefined? {id: Number(runnext.goId), entryFunc: runnext.executionContext!.func!}: undefined,
                    runq: runqEntries.map(entry => ({id: Number(entry.goId), entryFunc: entry.executionContext!.func!})),
                },
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
        const {procId, runnext, runqEntries, mId} = event;
        if (procId === undefined || mId === undefined) {
            throw new Error(`invalid runqStatusEvent (procId: ${procId}, mId: ${mId})`);
        }
        get().updateStructures([
            {
                mId: Number(mId),
                structureType: StructureType.LocalRunq,
                value: {
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
            },
        ]);
    },

    updateStructures: (structs: Structure[]) => {
        let updatedState: Partial<ThreadsSlice> = {};

        // Local structures.
        //
        // TODO: cover special case where a proc was added after initialization
        // and has later become idle (why does this happen?).
        const localStructs = structs.filter(struct => struct.mId !== undefined);
        const changedStructsByMId = new Map<number, Structure[]>();
        for (const struct of localStructs) {
            const {mId} = struct;
            let changedStructs = changedStructsByMId.get(mId);
            if (changedStructs === undefined) {
                changedStructs = [];
                changedStructsByMId.set(mId, changedStructs);
            }
            changedStructs.push(struct);
        }
        const threads = get().threads;
        for (const [mId, structs] of [...changedStructsByMId]) {
            const thread = threads.find((thread) => thread.mId === mId)
            if (thread === undefined) {
                console.warn(`thread with mId ${mId} has structure change but is not found in thread list`);
                continue;
            }
            for (const {structureType, value} of structs) {
                if (value === undefined) {
                    console.warn(`undefined value for mId ${mId} and structure type ${structureType} when updating structure state`);
                    continue;
                }
                switch (structureType) {
                    case StructureType.Executing:
                        thread.executing = value;
                        break;
                    case StructureType.LocalRunq:
                        checkAndApplyMPBindingChange(threads, mId, value.id, value);
                        break
                    default:
                        console.warn(`state change for m${mId} and structure type ${structureType} not applied`);
                }
            }
        }
        if (localStructs.length > 0) {
            updatedState.threads = [...threads];
        }

        set(() => (updatedState));
    }
})

// checkAndApplyMPBindingChange checks for possible change in m-p bindings.
function checkAndApplyMPBindingChange(threads: Thread[], mId: number, procId: number, newP: Proc | undefined = undefined): Thread[] {
    const existingThread = threads.find((thread) => thread.p?.id === procId);
    if (existingThread === undefined) {
        throw new Error(`no existing thread found for procId ${procId}`);
    }

    let targetThread = threads.find(thread => thread.mId === mId);
    if (targetThread === undefined) {
        targetThread = {mId, isScheduling: false};
        threads.push(targetThread);
    }
    const p = newP?? existingThread.p;
    existingThread.p = undefined;
    const oldP = targetThread.p;
    targetThread.p = p;
    threads.push({p: oldP, isScheduling: false});
    return threads.filter(thread => thread.mId !== undefined || thread.p !== undefined);
}

export const useBoundStore = create<CodePanelSlice & ThreadsSlice & SharedSlice>()(
    (...args) => ({
        ...createCodePanelSlice(...args),
        ...createThreadsSlice(...args),
        ...createSharedSlice(...args),
    })
);