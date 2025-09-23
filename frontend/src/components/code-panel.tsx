import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
import * as ace from 'brace';
import 'brace/mode/golang';
import 'brace/theme/solarized_light';
import type { Dispatch, SetStateAction } from 'react';
import { useEffect, useRef, useState, type MouseEventHandler } from 'react';
import { CompileAndRunRequest } from '../../proto/slowmo';
import { SlowmoServiceClient } from '../../proto/slowmo.client';
import { asStyleStr, clearUsedColors, mixPastelColor, pickPastelColor, type HSL } from '../lib/color-picker';
import { flushSync } from 'react-dom';


interface RunningCodeLinePerThread {
    lineNumber: number;
    goId: number;
    backgroundColor: HSL;
}

export default function CodePanel() {
    const [isRunning, setIsRunning] = useState(false);
    const [codeLines, setCodeLines] = useState<string[]>(['// Your Go code']);
    const [runningCodeLines, setRunningCodeLines] = useState<Map<number, RunningCodeLinePerThread>>(new Map());

    if (!isRunning) {
        return (
            <AceEditorWrapper
                codeLines={codeLines}
                setCodeLines={setCodeLines}
                setIsRunning={setIsRunning}
                runningCodeLines={runningCodeLines}
                setRunningCodeLines={setRunningCodeLines}
            ></AceEditorWrapper>
        );
    } else {
        return (
            <InstrumentedCode
                codeLines={codeLines}
                runningCodeLines={runningCodeLines}
            ></InstrumentedCode>
        );
    };
}

interface AceEditorWrapperProps {
    codeLines: string[];
    setCodeLines: Dispatch<SetStateAction<string[]>>;
    setIsRunning: Dispatch<SetStateAction<boolean>>;
    runningCodeLines: Map<number, RunningCodeLinePerThread>;
    setRunningCodeLines: Dispatch<SetStateAction<Map<number, RunningCodeLinePerThread>>>;
}

function AceEditorWrapper({codeLines, setCodeLines, setIsRunning, runningCodeLines, setRunningCodeLines}: AceEditorWrapperProps) {
    const elemRef = useRef<HTMLDivElement & {
        editor?: ace.Editor,
        slowmo?: {
            transport: GrpcWebFetchTransport,
            client: SlowmoServiceClient,
        },
    }>(null);
    useEffect(() => {
        if (!elemRef.current) {
            throw new Error("ref to ace editor wrapper element is null")
        }
        const elemId = elemRef.current!.id;
        var editor = ace.edit(elemId);
        editor.getSession().setMode('ace/mode/golang');
        editor.setTheme('ace/theme/solarized_light');
        // Set initial content of the editor.
        editor.setValue(codeLines.join('\n'));
        editor.clearSelection();
        elemRef.current.editor = editor;
    })

    async function handleClickRun() {
        if (!elemRef.current?.editor) {
            throw new Error("ace editor wrapper has no initialized editor")
        }
        if (!elemRef.current.slowmo) {
            const transport = new GrpcWebFetchTransport({
                baseUrl: import.meta.env.VITE_SLOWMO_SERVER_HOSTNAME,
            });
            const client = new SlowmoServiceClient(transport);
            elemRef.current.slowmo = {transport, client};
        }
        const { editor, slowmo } = elemRef.current;
        const { client } = slowmo;
        const source = editor.getValue();
        var request: CompileAndRunRequest = {
            source,
        };

        try {
            const stream = client.compileAndRun(request);
            setCodeLines(source.split('\n'));
            setIsRunning(true);
            // TODO: pull response stream processing logic out of this module, and
            // probably emit custom event instead of directly updating state here.
            for await (const msg of stream.responses) {
                switch (msg.compileAndRunOneof.oneofKind) {
                    case 'compileError':
                        console.log('compilation returns error: ', msg.compileAndRunOneof.compileError.errorMessage);
                        break;
                    case 'runtimeError':
                        console.log('runtime error: ', msg.compileAndRunOneof.runtimeError.errorMessage);
                        break;
                    case 'runtimeOutput':
                        console.log('runtime output: ', msg.compileAndRunOneof.runtimeOutput.output)
                        break
                    case 'runEvent':
                        const runEvent = msg.compileAndRunOneof.runEvent;
                        console.log('run event of type ', runEvent.probeEventOneof.oneofKind);
                        switch (runEvent.probeEventOneof.oneofKind) {
                            case 'delayEvent': {
                                const {mId, currentPc, goId} = runEvent.probeEventOneof.delayEvent;
                                if (mId === undefined || goId === undefined || currentPc === undefined || !currentPc.func?.startsWith('main') || currentPc.line === undefined) {
                                    throw new Error(`invalid delay event (mId: ${mId}, line: ${currentPc?.line})`);
                                }
                                const runningCodeLinesPerThread = runningCodeLines.get(Number(mId));
                                if (!runningCodeLinesPerThread) {
                                    runningCodeLines.set(Number(mId), {
                                        lineNumber: currentPc.line,
                                        backgroundColor: pickPastelColor(Number(goId)),
                                        goId: Number(goId),
                                    });
                                } else {
                                    runningCodeLinesPerThread.lineNumber = currentPc.line;
                                }
                                flushSync(() => {
                                    setRunningCodeLines(new Map(runningCodeLines));
                                });
                                break;
                            }
                            case 'scheduleEvent': {
                                const {mId} = runEvent.probeEventOneof.scheduleEvent;
                                if (mId === undefined) {
                                    throw new Error(`invalid schedule event (mId: ${mId})`);
                                }
                                runningCodeLines.delete(Number(mId));
                                flushSync(() => {
                                    setRunningCodeLines(new Map(runningCodeLines));
                                });
                                break;
                            }
                        }
                        break;
                    default:
                        console.log('unexpected stream message type: ', msg.compileAndRunOneof.oneofKind);
                }
            }
        } finally {
            setRunningCodeLines(new Map());
            setIsRunning(false);
            clearUsedColors();
        }
    }

    return (
        <div className='code-panel'>
            <div id="banner">
                <div id='head'>Go Runtime in Slowmo</div>
                <Button id='button-run' onClick={handleClickRun}>Run</Button>
            </div>
            <div ref={elemRef} className='golang-editor' id='ace-editor-wrapper'></div>
        </div>
    );
}

interface InstrumentedCodeProps {
    codeLines: string[];
    runningCodeLines: Map<number, RunningCodeLinePerThread>;
}

function InstrumentedCode({codeLines, runningCodeLines}: InstrumentedCodeProps) {
    const lineNumToBgColor = new Map<number, HSL>();
    runningCodeLines.forEach((val) => {
        const {lineNumber, backgroundColor} = val;
        const currBgColor = lineNumToBgColor.get(lineNumber);
        if (!currBgColor) {
            lineNumToBgColor.set(lineNumber, backgroundColor);
        } else {
            lineNumToBgColor.set(lineNumber, mixPastelColor(currBgColor, backgroundColor));
        }
    });

    const spans = [], lineNums = [];
    for (let i = 0; i < codeLines.length; i++) {
        const codeLine = codeLines[i];
        const bgColor = lineNumToBgColor.get(i + 1);
        if (bgColor) {
            spans.push(<span key={i} className='instrumented-code-line' style={{background: asStyleStr(bgColor)}}>{codeLine}</span>);
        } else {
            spans.push(<span key={i} className='instrumented-code-line'>{codeLine}</span>);
        }
        lineNums.push(<span key={'line-'+i} className='line-number'>{i + 1}</span>);
    }
    return (
        <div className='code-panel'>
            <div id="banner">
                <div id='head'>Go Runtime in Slowmo</div>
                <Button id='button-run'>Run</Button>
            </div>
            <div className='golang-editor'>
                <div id='instrumented-code-linenums'>
                    {lineNums}
                </div>
                <div id='instrumented-code'>
                    {spans}
                </div>
            </div>
        </div>
    );
}

interface RunButtonProps {
    id: string,
    onClick?: MouseEventHandler,
    children: string,
}

function Button({id, onClick, children}: RunButtonProps) {
    return onClick? (
        <button id={id} onClick={onClick}>
            {children}
        </button>
    ): (
        <button id={id} disabled={true}>
            {children}
        </button>
    );
}