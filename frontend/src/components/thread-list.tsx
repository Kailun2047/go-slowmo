import { useEffect, useRef } from "react";
import { asStyleStr, pickPastelColor } from "../lib/color-picker";
import { useBoundStore } from "./store";

export function ThreadList() {
    const threads = useBoundStore((state) => state.threads);
    const resetIsScheduling = useBoundStore((state) => state.resetIsScheduling);
    const schedSpinnerWrapperElemsRef = useRef<Map<number, (HTMLDivElement & {
        listenerAdded?: boolean;
    }) | null>>(new Map());

    useEffect(() => {
        [...schedSpinnerWrapperElemsRef.current].map(([mId, elem]) => {
            if (!elem) {
                throw new Error(`spinner wrapper elem for mId ${mId} is null`);
            }
            const handleTransitionend = (event: TransitionEvent) => {
                if (event.propertyName === 'transform') {
                    resetIsScheduling(mId);
                }
            }
            if (!elem.listenerAdded) {
                elem.addEventListener('transitionend', handleTransitionend);
                elem.listenerAdded = true;
                return () => {
                    elem.removeEventListener('transitionend', handleTransitionend);
                };
            }
        })
    }, [threads]);

    const individualThreads = threads.map((thread, i) => {
        const {mId, isScheduling, p, executing} = thread;

        let goExecutingG = (
            <div className='go-executing-g-wrapper'></div>
        );
        if (executing !== undefined) {
            goExecutingG = (
                <div className='go-executing-g-wrapper'>
                    <div className='go-g' style={{backgroundColor: asStyleStr(pickPastelColor(executing.id))}}>
                        {'g' + executing.id}<br />
                        {executing.entryFunc}
                    </div>
                </div>
            );
        }

        let scheduleSpinner = (
            <div className='schedule-spinner-wrapper'></div>
        );
        let goM = (
            <div className='go-m-wrapper'></div>
        );
        if (mId !== undefined) {
            scheduleSpinner = (
                <div ref={(elem) => {
                    schedSpinnerWrapperElemsRef.current.set(mId, elem);
                    return () => {
                        schedSpinnerWrapperElemsRef.current.delete(mId)
                    };
                }} className={'schedule-spinner-wrapper' + (isScheduling? ' schedule-spinner-wrapper-transition': '')}>
                    <div className='schedule-spinner-circle'></div>
                    <div className='schedule-spinner-arrow'></div>
                </div>
            );
            goM = (
                <div className='go-m-wrapper'>
                    <div className='go-m'></div>
                    <div className='go-m-text'>{'m' + mId}</div>
                </div>
            );
        }

        let goP = (
            <div className='go-p-wrapper'></div>
        );
        if (p !== undefined) {
            const runq = (p.runnext? [p.runnext, ...p.runq]: p.runq).map((g) => (
                <div className='go-g' key={'g'+g.id} style={{backgroundColor: asStyleStr(pickPastelColor(g.id))}}>
                    {'g' + g.id}<br />
                    {g.entryFunc}
                </div>
            ));
            goP = (
                <div className='go-p-wrapper' style={{borderWidth: '2px', borderStyle: 'dashed', borderColor: 'gray'}}>
                    <div className='go-p'>{'p' + p.id}</div>
                    <div className='go-runq'>{runq}</div>
                </div>
            )
        }

        return (
            <div className='thread' key={'thread-' + i}>
                {goExecutingG}
                {scheduleSpinner}
                {goM}
                {goP}
            </div>
        );
    });

    return (
        <div className='thread-list'>
            {individualThreads}
        </div>
    );
}

// interface ThreadProps {
//     thread: IndividualThread;
// }

// function IndividualThread({thread}: ThreadProps) {
//     const {mId, isScheduling, p, executing} = thread;
//     const resetIsScheduling = useBoundStore((state) => state.resetIsScheduling);

//     const schedSpinnerWrapperElemRef = useRef<HTMLDivElement>(null);
//     useEffect(() => {
//         schedSpinnerWrapperElemRef.current?.addEventListener('transitionend', (event) => {
//             if (mId === undefined) {
//                 throw new Error(`found undefined mId when handling transitionend event`);
//             }
//             if (event.propertyName === 'transform') {
//                 resetIsScheduling(mId);
//             }
//         })
//     }, []);

//     let goExecutingG = (
//         <div className='go-executing-g-wrapper'></div>
//     );
//     if (executing !== undefined) {
//         goExecutingG = (
//             <div className='go-executing-g-wrapper'>
//                 <div className='go-g' style={{backgroundColor: asStyleStr(pickPastelColor(executing.id))}}>
//                     {'g' + executing.id}<br />
//                     {executing.entryFunc}
//                 </div>
//             </div>
//         );
//     }

//     let scheduleSpinner = (
//         <div ref={schedSpinnerWrapperElemRef} className='schedule-spinner-wrapper'></div>
//     );
//     let goM = (
//         <div className='go-m-wrapper'></div>
//     );
//     if (mId !== undefined) {
//         scheduleSpinner = (
//             <div ref={schedSpinnerWrapperElemRef} className={'schedule-spinner-wrapper' + (isScheduling? ' schedule-spinner-wrapper-transition': '')}>
//                 <div className='schedule-spinner-circle'></div>
//                 <div className='schedule-spinner-arrow'></div>
//             </div>
//         );
//         goM = (
//             <div className='go-m-wrapper'>
//                 <div className='go-m'></div>
//                 <div className='go-m-text'>{'m' + mId}</div>
//             </div>
//         );
//     }

//     let goP = (
//         <div className='go-p-wrapper'></div>
//     );
//     if (p !== undefined) {
//         const runq = (p.runnext? [p.runnext, ...p.runq]: p.runq).map((g) => (
//             <div className='go-g' key={'g'+g.id} style={{backgroundColor: asStyleStr(pickPastelColor(g.id))}}>
//                 {'g' + g.id}<br />
//                 {g.entryFunc}
//             </div>
//         ));
//         goP = (
//             <div className='go-p-wrapper' style={{borderWidth: '2px', borderStyle: 'dashed', borderColor: 'gray'}}>
//                 <div className='go-p'>{'p' + p.id}</div>
//                 <div className='go-runq'>{runq}</div>
//             </div>
//         )
//     }

//     return (
//         <div className='thread'>
//             {goExecutingG}
//             {scheduleSpinner}
//             {goM}
//             {goP}
//         </div>
//     );
// }