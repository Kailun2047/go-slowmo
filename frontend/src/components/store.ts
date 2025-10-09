import { create as actualCreate, type StateCreator } from "zustand";
import { ScheduleReason, StructureType } from "../../proto/slowmo";
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
    initThreads: (numCpu: number) => void;
    resetIsScheduling: (mId: number) => void;
}

interface SharedSlice {
    // structureStateBuffer collects corresponding structure states received
    // from structure state events for each notification event. This piece of
    // store is used to keep intermediate application state and not intended to
    // be used directly in components.
    structureStateCollections: Structure[][];
    handleScheduleEvent: (mId: number, reason: ScheduleReason, procId?: number) => void;
    handleNewProcEvent: (mId: number) => void;
    handleNotification: (targetStructs: Structure[]) => void;
    handleStructureState: (receivedStructs: Structure[]) => void;
    // handleStructureStateChange is to be invoked upon complete collection of
    // all structure states for a notification event to reflect changed
    // structures in components.
    updateStructures: (collectedStructures: Structure[]) => void;
}

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
> = (set, get) => ({
    threads: [],

    // initThreads is called once upon receiving num_cpu from server.
    initThreads: (numCpu: number) => {
        const threads: Thread[] = [];
        for (let i = 0; i < numCpu; i++) {
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

    resetIsScheduling: (mId: number) => {
        const threads = get().threads;
        const thread = threads.find(thread => thread.mId === mId);
        if (thread === undefined) {
            throw new Error(`target thread (mId: ${mId}) not found when reset isScheduling`);
        }
        thread.isScheduling = false;
        set(() => ({
            threads: [...threads],
        }));
    },
})

const createSharedSlice: StateCreator<
    CodePanelSlice & ThreadsSlice & SharedSlice, [], [], SharedSlice
> = (set, get) => ({
    structureStateCollections: [],

    handleScheduleEvent: (mId: number, reason: ScheduleReason, procId?: number) => {
        if (procId === undefined) {
            throw new Error('unexpected new M without procId, skipping assignment');
        }
        get().handleNotification([
            {mId, structureType: StructureType.Executing},
        ]);

        // Checks for possible change in m-p bindings.
        const threads = get().threads;
        const existingThread = threads.find((thread) => thread.p?.id === procId);
        if (existingThread === undefined) {
            throw new Error(`no existing thread found for procId ${procId}, skipping assignment`);
        }
        let renderIsSchedulingDelay = 0;
        if (existingThread.mId === undefined) {
            existingThread.mId = mId;
        } else if (existingThread.mId !== mId) {
            // If p is already assigned to a different M, transfer the p to the
            // new M and leave the old M with no p.
            const p = existingThread.p;
            existingThread.p = undefined;
            let targetThread = threads.find(thread => thread.mId === mId);
            if (targetThread === undefined) {
                // Add to thread if this is a new M.
                threads.push({
                    mId,
                    isScheduling: false,
                    p,
                });
                // When a new thread is added, introduce a delay between
                // rendering the initial state and rendering change of
                // isSchedule to avoid having the element in its final state at
                // birth.
                set(() => ({
                    threads: [...threads],
                }));
                renderIsSchedulingDelay = 10;
            } else {
                targetThread.p = p;
            }
        }

        setTimeout(() => {
            set((state) => ({
                threads: [...threads.map((thread) => thread.mId === mId? {...thread, isScheduling: true}: thread)],
                runningCodeLines: new Map([...state.runningCodeLines].filter(([k, _]) => k !== mId)),
            }))
        }, renderIsSchedulingDelay);
    },

    handleNewProcEvent: (mId: number) => {
        get().handleNotification([
            {mId, structureType: StructureType.LocalRunq},
        ]);
    },

    handleNotification: (targetStructs: Structure[]) => {
        set((state) => ({
            structureStateCollections: [...state.structureStateCollections, targetStructs],
        }));
    },

    handleStructureState: (receivedStructs: Structure[]) => {
        for (const {mId, structureType, value} of receivedStructs) {
            let idxInCollection = -1;
            const collections = get().structureStateCollections;
            for (let i = 0; i < collections.length; i++) {
                const structsToCollect = collections[i];
                idxInCollection = structsToCollect.findIndex(targetStruct => targetStruct.mId === mId && targetStruct.structureType === structureType);
                if (idxInCollection !== -1) {
                    structsToCollect[idxInCollection].value = value;
                    // Update structures and remove collection once states of
                    // all target structs are collected.
                    if (structsToCollect.find(struct => struct.value === undefined) === undefined) {
                        set(() => ({
                            structureStateCollections: [...collections.slice(0, i), ...collections.slice(i + 1)],
                        }));
                        get().updateStructures(structsToCollect);
                    }
                    break;
                }
            }
            if (idxInCollection === -1) {
                console.warn(`received structure (mId: ${mId}, type: ${structureType}) is not among any targets`);
            }
        }
    },

    updateStructures: (collectedStructures: Structure[]) => {
        const changedStructsByMId = new Map<number, Structure[]>();
        for (const struct of collectedStructures) {
            const {mId} = struct;
            let changedStructs = changedStructsByMId.get(mId);
            if (changedStructs === undefined) {
                changedStructs = [];
                changedStructsByMId.set(mId, changedStructs);
            }
            changedStructs.push(struct);
        }
        const changedStructureTypes = new Set<StructureType>;
        for (const [mId, structs] of [...changedStructsByMId]) {
            const thread = get().threads.find((thread) => thread.mId === mId)
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
                        thread.p = value;
                        break
                    default:
                        console.warn(`state change for m${mId} and structure type ${structureType} not applied`);
                }
                changedStructureTypes.add(structureType);
            }
            let updatedState: Partial<ThreadsSlice> = {};
            if (changedStructureTypes.has(StructureType.Executing) || changedStructureTypes.has(StructureType.LocalRunq)) {
                updatedState.threads = [...get().threads];
            }
            set(() => (updatedState));
        }
    }
})

export const useBoundStore = create<CodePanelSlice & ThreadsSlice & SharedSlice>()(
    (...args) => ({
        ...createCodePanelSlice(...args),
        ...createThreadsSlice(...args),
        ...createSharedSlice(...args),
    })
);