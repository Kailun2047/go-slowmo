import { useBoundStore } from "./store";

export function ThreadList() {
    const threads = useBoundStore((state) => state.threads);

    return (
        <div className='thread-list'>
            {threads.map((thread) => (
                <Thread key={'thread-' + thread.mId} heightPercentage={100 / threads.length} />
            ))}
        </div>
    );
}

interface ThreadProps {
    heightPercentage: number;
}

function Thread({heightPercentage}: ThreadProps) {
    return (
        <div className='thread' style={{height: `${heightPercentage}%`}}>
            Thread structure placeholder
        </div>
    );
}