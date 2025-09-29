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

interface Thread {
    mId: number;
    isScheduling: boolean;
}

interface ThreadsSlice {
    threads: Thread[];
    addThread: (mId: number) => void;
}

interface SharedSlice {
    handleScheduleEvent: (mId: number, reason: ScheduleReason) => void;
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
> = (set) => ({
    threads: [],
    addThread: (mId: number) => set((state) => ({
        threads: [...state.threads, {mId, isScheduling: false}]
    })),
})

const sharedSlice: StateCreator<
    CodePanelSlice & ThreadsSlice, [], [], SharedSlice
> = (set, get) => ({
    handleScheduleEvent: (mId: number, reason: ScheduleReason) => {
        if (reason === ScheduleReason.MSTART) {
            get().addThread(mId);
        } else {
            set((state) => ({
                threads: state.threads.map((thread) => thread.mId === mId? {...thread, isScheduling: true}: thread),
                runningCodeLines: new Map([...state.runningCodeLines].filter(([k, _]) => k === mId)),
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