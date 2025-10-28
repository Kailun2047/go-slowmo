import { isNil } from "lodash";
import { OutputType, useBoundStore, useOutputStore } from "./store";

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
            systemOutput = (
                <span className='system-output'>
                    {
                        output.type === OutputType.Requesting? 'Waiting for remote server...':
                            output.type === OutputType.RequestError? `Request failed: ${output.requestError}`:
                                output.type === OutputType.CompilationError? 'Go build failed.':
                                    'Program exited.'
                    }
                </span>
            );
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