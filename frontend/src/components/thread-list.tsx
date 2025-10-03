import { asStyleStr, pickPastelColor } from "../lib/color-picker";
import { useBoundStore, type Thread } from "./store";

export function ThreadList() {
    const threads = useBoundStore((state) => state.threads);

    return (
        <div className='thread-list'>
            {threads.map((thread, i) => (
                <Thread key={'thread-' + i} thread={thread} />
            ))}
        </div>
    );
}

interface ThreadProps {
    thread: Thread;
}

function Thread({thread}: ThreadProps) {
    const {mId, isScheduling, p} = thread;

    let scheduleSpinner = (
        <div className={'schedule-spinner-wrapper'}></div>
    );
    let goM = (
        <div className='go-m-wrapper'></div>
    );

    if (mId !== undefined) {
        scheduleSpinner = (
            <div className='schedule-spinner-wrapper'>
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
                {'g' + g.id}
                {'entry: ' + g.entryFunc}
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
        <div className='thread'>
            {scheduleSpinner}
            {goM}
            {goP}
        </div>
    );
}