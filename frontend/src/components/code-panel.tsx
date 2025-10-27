import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
import * as ace from 'brace';
import 'brace/mode/golang';
import 'brace/theme/solarized_light';
import { useEffect, useRef, type MouseEventHandler } from 'react';
import { CompileAndRunRequest, NotificationEvent, StructureStateEvent } from '../../proto/slowmo';
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
    const handleNewProcEvent = useBoundStore((state) => state.handleNewProcEvent);
    const handleExecuteEvent = useBoundStore((state) => state.handleExecuteEvent);
    const handleRunqStatusEvent = useBoundStore((state) => state.handleRunqStatusEvent);
    const initThreads = useBoundStore((state) => state.initThreads);
    const handleGoparkEvent = useBoundStore((state) => state.handleGoparkEvent);
    const handleGoreadyEvent = useBoundStore((state) => state.handleGoreadyEvent);

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
                    case 'gomaxprocs':
                        initThreads(msg.compileAndRunOneof.gomaxprocs);
                        break;
                    case 'runEvent':
                        const runEvent = msg.compileAndRunOneof.runEvent;
                        console.log('run event of type ', runEvent.probeEventOneof.oneofKind);

                        switch (runEvent.probeEventOneof.oneofKind) {
                            case 'delayEvent': {
                                const {mId, currentPc, goId} = runEvent.probeEventOneof.delayEvent;
                                if (mId === undefined || goId === undefined || currentPc === undefined || currentPc.func === undefined || currentPc.line === undefined) {
                                    throw new Error(`invalid delay event (mId: ${mId}, line: ${currentPc?.line})`);
                                }
                                if (currentPc.func.startsWith('main')) {
                                    handleDelayEvent(Number(mId), currentPc.line, Number(goId));
                                }
                                break;
                            }
                            case 'notificationEvent':
                                processNotificationEvent(runEvent.probeEventOneof.notificationEvent)
                                break;
                            case 'structureStateEvent':
                                processStructureStateEvent(runEvent.probeEventOneof.structureStateEvent);
                                break;
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

    function processNotificationEvent(event: NotificationEvent): void {
        switch (event.notificationOneof.oneofKind) {
            case 'scheduleEvent': {
                handleScheduleEvent(event.notificationOneof.scheduleEvent);
                break;
            }
            case 'newProcEvent': {
                handleNewProcEvent(event.notificationOneof.newProcEvent);
                break;
            }
            case 'goparkEvent': {
                handleGoparkEvent(event.notificationOneof.goparkEvent);
                break;
            }
            default:
                console.warn(`unknown notification event type ${event.notificationOneof.oneofKind}`)
        }
    }

    function processStructureStateEvent(event: StructureStateEvent): void {
        switch (event.structureStateOneof.oneofKind) {
            case 'executeEvent': {
                handleExecuteEvent(event.structureStateOneof.executeEvent);
                break;
            }
            case 'runqStatusEvent': {
                handleRunqStatusEvent(event.structureStateOneof.runqStatusEvent);
                break;
            }
            case 'goreadyEvent': {
                handleGoreadyEvent(event.structureStateOneof.goreadyEvent);
                break;
            }
            default:
                console.warn(`unknown structure state event type ${event.structureStateOneof.oneofKind}`);
        }
    }

    return (
        <div className='code-panel code-panel-editing'>
            <div id="banner">
                <h1 id='head'>Go Slowmo</h1>
                <Button className='button-run' onClick={handleClickRun}>Compile & Run</Button>
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
                <h1 id='head'>Go Slowmo</h1>
                <Button className='button-run button-run-running'>Compile & Run</Button>
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
    className: string
    onClick?: MouseEventHandler,
    children: string,
}

function Button({className: classNames, onClick, children}: RunButtonProps) {
    return onClick? (
        <button className={classNames} onClick={onClick}>
            {children}
        </button>
    ): (
        <button className={classNames} disabled={true}>
            {children}
        </button>
    );
}

