import { create as actualCreate, type StateCreator } from "zustand";
import { pickPastelColor, type HSL } from "../lib/color-picker";
import { ScheduleReason } from "../../proto/slowmo";

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
    assignM: (mId: number, procId?: number) => void;
}

interface SharedSlice {
    handleScheduleEvent: (mId: number, reason: ScheduleReason, procId?: number) => void;
}

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
    // 
    // TODO: visualize G0 properly.
    initThreads: (numCpu: number) => {
        const threads: Thread[] = [];
        for (let i = 0; i < numCpu; i++) {
            threads.push({
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
    // assignM sets mId for thread on mstart.
    assignM: (mId: number, procId?: number) => {
        const threads = get().threads;
        if (procId === undefined) {
            console.warn('unexpected new M without procId, skipping assignment');
            return;
        }
        const threadIdx = threads.findIndex((thread) => thread.p?.id === procId);
        if (threadIdx === -1) {
            console.warn(`no existing thread found for procId ${procId}, skipping assignment`);
            return;
        }
        if (threads[threadIdx].mId !== undefined) {
            // If p is already assigned to an M, transfer the p to the new M and leave the old M with no p.
            const p = threads[threadIdx].p;
            threads[threadIdx].p = undefined;
            threads.push({
                mId,
                isScheduling: false,
                p,
            });
        } else {
            threads[threadIdx].mId = mId;
        }
        set(() => ({
            threads,
        }));
    },
})

const sharedSlice: StateCreator<
    CodePanelSlice & ThreadsSlice, [], [], SharedSlice
> = (set, get) => ({
    handleScheduleEvent: (mId: number, reason: ScheduleReason, procId?: number) => {
        if (reason === ScheduleReason.MSTART) {
            get().assignM(mId, procId);
        } else {
            set((state) => ({
                threads: state.threads.map((thread) => thread.mId === mId? {...thread, isScheduling: true}: thread),
                runningCodeLines: new Map([...state.runningCodeLines].filter(([k, _]) => k !== mId)),
            }))
        }
    }
})

export const useBoundStore = create<CodePanelSlice & ThreadsSlice & SharedSlice>()(
    (...args) => ({
        ...createCodePanelSlice(...args),
        ...createThreadsSlice(...args),
        ...sharedSlice(...args),
    })
);