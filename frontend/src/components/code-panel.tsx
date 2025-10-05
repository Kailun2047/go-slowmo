import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
import * as ace from 'brace';
import 'brace/mode/golang';
import 'brace/theme/solarized_light';
import { useEffect, useRef, type MouseEventHandler } from 'react';
import { CompileAndRunRequest, NotificationEvent } from '../../proto/slowmo';
import { SlowmoServiceClient } from '../../proto/slowmo.client';
import { asStyleStr, clearUsedColors, mixPastelColors, type HSL } from '../lib/color-picker';
import { resetAllStores, useAceEditorWrapperStore, useBoundStore } from './store';


interface RunningCodeLinePerThread {
    lineNumber: number;
    goId: number;
    backgroundColor: HSL;
}

export default function CodePanel() {
    const isRunning = useBoundStore((state) => state.isRunning);

    if (!isRunning) {
        return (
            <AceEditorWrapper></AceEditorWrapper>
        );
    } else {
        return (
            <InstrumentedEditor></InstrumentedEditor>
        );
    };
}

function AceEditorWrapper() {
    const codeLines = useAceEditorWrapperStore((state) => state.codeLines);
    const setCodeLines = useAceEditorWrapperStore((state) => state.setCodeLines);
    const setIsRunning = useBoundStore((state) => state.setIsRunning);
    const handleDelayEvent = useBoundStore((state) => state.handleDelayEvent);
    const handleScheduleEvent = useBoundStore((state) => state.handleScheduleEvent);
    const initThreads = useBoundStore((state) => state.initThreads);

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
    }, [])

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
                    case 'numCpu':
                        initThreads(msg.compileAndRunOneof.numCpu);
                        break;
                    case 'runEvent':
                        const runEvent = msg.compileAndRunOneof.runEvent;
                        console.log('run event of type ', runEvent.probeEventOneof.oneofKind);
                        switch (runEvent.probeEventOneof.oneofKind) {
                            case 'notificationEvent': {
                                handleNotificationEvent(runEvent.probeEventOneof.notificationEvent)
                                break;
                            }
                            case 'structureStateEvent': {
                                // TODO: diff structure state and animate
                                // goroutine movement.
                                break;
                            }
                        }
                        break;
                    default:
                        console.warn(`unknown stream message type: ${msg.compileAndRunOneof.oneofKind}`);
                }
            }
        } finally {
            resetAllStores();
            clearUsedColors();
        }
    }

    function handleNotificationEvent(notificationEvent: NotificationEvent): void {
        switch (notificationEvent.notificationOneof.oneofKind) {
            case 'delayEvent': {
                const {mId, currentPc, goId} = notificationEvent.notificationOneof.delayEvent;
                if (mId === undefined || goId === undefined || currentPc === undefined || currentPc.func === undefined || currentPc.line === undefined) {
                    throw new Error(`invalid delay event (mId: ${mId}, line: ${currentPc?.line})`);
                }
                if (currentPc.func.startsWith('main')) {
                    handleDelayEvent(Number(mId), currentPc.line, Number(goId));
                }
                break;
            }
            case 'scheduleEvent': {
                const {mId, reason, procId} = notificationEvent.notificationOneof.scheduleEvent;
                if (mId === undefined) {
                    throw new Error(`invalid schedule event (mId: ${mId})`);
                }
                handleScheduleEvent(Number(mId), reason, procId !== undefined? Number(procId) : undefined);
                console.log(`handled schedule event for mId ${Number(mId)} and reason ${reason}`);
                break;
            }
            default:
                console.warn(`unknown notification event type ${notificationEvent.notificationOneof.oneofKind}`)
        }
    }

    return (
        <div className='code-panel'>
            <div id="banner">
                <div id='head'>Go Slowmo</div>
                <Button id='button-run' onClick={handleClickRun}>Run</Button>
            </div>
            <div ref={elemRef} className='golang-editor' id='ace-editor-wrapper'></div>
        </div>
    );
}

function InstrumentedEditor() {
    const codeLines = useAceEditorWrapperStore((state) => state.codeLines);
    const runningCodeLines = useBoundStore((state) => state.runningCodeLines);

    const lineNumToThreads = new Map<number, (Pick<RunningCodeLinePerThread, 'backgroundColor' | 'goId'> & {mId: number})[]>();
    runningCodeLines.forEach((val, mId) => {
        const {lineNumber, backgroundColor, goId} = val;
        const currThreads = lineNumToThreads.get(lineNumber);
        if (currThreads === undefined) {
            lineNumToThreads.set(lineNumber, [{backgroundColor, goId, mId}]);
        } else {
            lineNumToThreads.set(lineNumber, [...currThreads, {backgroundColor, goId, mId}]);
        }
    });

    const spans = [], lineNums = [], cursors = [];
    for (let i = 0; i < codeLines.length; i++) {
        const codeLine = codeLines[i];
        const threads = lineNumToThreads.get(i + 1);
        const execs = [];
        if (threads !== undefined && threads.length > 0) {
            const {mId: firstMid, backgroundColor: firstBgColor, goId: firstGoId} = threads[0];
            let bgColor = firstBgColor;
            execs.push(<em key='exec-0' style={{color: asStyleStr(firstBgColor)}}>{'m' + firstMid + ':g' + firstGoId}</em>);
            for (let j = 1; j < threads.length; j++) {
                const {mId, goId, backgroundColor} = threads[j];
                bgColor = mixPastelColors(bgColor, backgroundColor);
                execs.push(<em key={'exec-'+j} style={{color: asStyleStr(backgroundColor)}}>{'m' + mId + ':g' + goId}</em>);
            }
            spans.push(<span key={i} className='instrumented-line' style={{background: asStyleStr(bgColor)}}>{codeLine}</span>);
        } else {
            spans.push(<span key={i} className='instrumented-line'>{codeLine}</span>);
        }
        lineNums.push(<span key={'line-'+i} className='instrumented-line'>{i + 1}</span>);
        cursors.push(<span key={'cursor-'+i} className='instrumented-line'>{execs}</span>);
    }
    return (
        <div className='code-panel'>
            <div id="banner">
                <div id='head'>Go Slowmo</div>
                <Button id='button-run'>Run</Button>
            </div>
            <div className='golang-editor'>
                <div id='instrumented-code-linenums'>
                    {lineNums}
                </div>
                <div id='instrumented-code'>
                    {spans}
                </div>
                <div id='instrumented-cursors'>
                    {cursors}
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

