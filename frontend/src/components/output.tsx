import { isNil } from "lodash";
import { OutputType, useBoundStore, useOutputStore } from "./store";
import { useEffect } from "react";

export function Output() {
    const isRunning = useBoundStore((state) => !!(state.isRequested?.isRunning));
    const output = useOutputStore((state) => state.output);

    let programOutput = undefined, systemOutput = undefined;
    if (!isNil(output)) {
        if ((output.type === undefined || output.type === OutputType.ProgramExited) && !isNil(output.runtimeOutput)) {
            programOutput = (
                <span className='compile-and-run-output'>{output.runtimeOutput}</span>
            );
        } else if (output.type === OutputType.CompilationError) {
            programOutput = (
                <span className='compile-and-run-output'>{output.compilationError}</span>
            );
        }
        if (output.type !== undefined) {
            systemOutput = output.type === OutputType.Requesting? (<WaitPrompt waitTimeStr={import.meta.env.VITE_REMOTE_SERVER_WAIT_TIME}></WaitPrompt>):
            output.type === OutputType.RequestError? (<span className='system-output'>{`Request failed: ${output.requestError}`}</span>)
            : output.type === OutputType.CompilationError? (<span className='system-output'>Go build failed.</span>)
            : <span className='system-output'>{`Program exited${!isNil(output.err)? `: ${output.err}`: ''}.`}</span>;
        }
    }

    return (
        <div className={'output-wrapper' + (isRunning? ' output-wrapper-running': '')}>
            <pre className='output'>
                {programOutput}
                {systemOutput}
            </pre>
        </div>
    );
}

function WaitPrompt({waitTimeStr}: {waitTimeStr: string}) {
    const requestingWaitCount = useOutputStore().requestingWaitCount;
    const incrementRequestingWaitCount = useOutputStore().incrementRequestingWaitCount;
    const resetRequestingWaitCount = useOutputStore().resetRequestingWaitCount;

    useEffect(() => {
        const id = setInterval(() => {
            incrementRequestingWaitCount(1);
        }, 1000);
        return () => {
            resetRequestingWaitCount();
            clearInterval(id);
        };
    }, [incrementRequestingWaitCount, resetRequestingWaitCount]);

    if (waitTimeStr) {
        return (<span className='system-output'>
            {`Waiting for remote server. This could take up to ${waitTimeStr} (you can try `}
            <a href='https://github.com/Kailun2047/go-slowmo?tab=readme-ov-file#running-locally' target="_blank">running locally</a>
            {` instead).\n\nWaited for ${requestingWaitCount} seconds...`}
        </span>)
    } else {
        return (<span className='system-output'>
            Waiting for remote server...
        </span>)
    }
}