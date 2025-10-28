import { asStyleStr, pickPastelColor } from "../lib/color-picker";
import { useBoundStore } from "./store";

export function ThreadList() {
    const threads = useBoundStore((state) => state.threads);
    const isRunning = useBoundStore((state) => !!(state.isRequested?.isRunning));

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
                <div className={'schedule-spinner-wrapper' + (isScheduling? ' schedule-spinner-wrapper-animation': '')}>
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
            <div className='go-struct-wrapper' style={{borderColor: "transparent"}}></div>
        );
        if (p !== undefined) {
            const runq = (p.runnext? [p.runnext, ...p.runq]: p.runq).map((g) => (
                <div className='go-g' key={'g'+g.id} style={{backgroundColor: asStyleStr(pickPastelColor(g.id))}}>
                    {'g' + g.id}<br />
                    {g.entryFunc}
                </div>
            ));
            goP = (
                <div className='go-struct-wrapper' style={{borderColor: 'gray'}}>
                    <div className='go-struct-name'>{'p' + p.id}</div>
                    <div className='go-struct'>{runq}</div>
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

    return isRunning? (
        <div className='thread-list'>
            {individualThreads}
        </div>
    ): undefined;
}
