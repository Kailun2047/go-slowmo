import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
import * as ace from 'brace';
import 'brace/mode/golang';
import 'brace/theme/solarized_light';
import { isNil } from 'lodash';
import { useEffect, useRef, type ChangeEvent, type ChangeEventHandler, type MouseEventHandler, type Ref } from 'react';
import { useSearchParams } from 'react-router';
import { AuthnChannel, CompileAndRunRequest, NotificationEvent, StructureStateEvent } from '../../proto/slowmo';
import { SlowmoServiceClient } from '../../proto/slowmo.client';
import { asStyleStr, clearUsedColors, mixPastelColors, type HSL } from '../lib/color-picker';
import { resetAllStores, useAceEditorWrapperStore, useBoundStore, useOutputStore } from './store';


interface RunningCodeLinePerThread {
    lineNumber: number;
    goId: number;
    backgroundColor: HSL;
}

export default function CodePanel() {
    const isRunning = useBoundStore((state) => !!(state.isRequested?.isRunning));

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

const initCode = `// You can edit this code!
package main

import (
	"log"
	"math/rand"
	"sync"
	"time"
)

func greet(word string) {
	log.Println(word)
}

func main() {
	var wg sync.WaitGroup

	startTime := time.Now().UnixMilli()
	defer func() {
		endTime := time.Now().UnixMilli()
		log.Printf("Time elapsed: %d ms", endTime-startTime)
	}()

	words := []string{"welcome","to","go-slowmo"}

	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			greet(words[rand.Intn(len(words))])
		}()
	}

	wg.Wait()
}`;

function AceEditorWrapper() {
    const setCodeLines = useAceEditorWrapperStore((state) => state.setCodeLines);
    const isAuthenticated = useAceEditorWrapperStore((state) => state.isAuthenticated);
    const setIsAuthenticated = useAceEditorWrapperStore((state) => state.setIsAuthenticated);

    const setIsRequested = useBoundStore((state) => state.setIsRequested);
    const handleDelayEvent = useBoundStore((state) => state.handleDelayEvent);
    const handleScheduleEvent = useBoundStore((state) => state.handleScheduleEvent);
    const handleNewProcEvent = useBoundStore((state) => state.handleNewProcEvent);
    const handleExecuteEvent = useBoundStore((state) => state.handleExecuteEvent);
    const handleRunqStatusEvent = useBoundStore((state) => state.handleRunqStatusEvent);
    const initThreads = useBoundStore((state) => state.initThreads);
    const handleGoparkEvent = useBoundStore((state) => state.handleGoparkEvent);
    const handleGoreadyEvent = useBoundStore((state) => state.handleGoreadyEvent);

    const outputRequesting = useOutputStore((state) => state.outputRequesting);
    const outputRequestError = useOutputStore((state) => state.outputRequestError);
    const outputCompilationError = useOutputStore((state) => state.outputCompilatioError);
    const outputProgramExit = useOutputStore((state) => state.outputProgramExit);
    const outputRuntimeOutput = useOutputStore((state) => state.outputRuntimeOutput);
    const outputProgramStart = useOutputStore((state) => state.outputProgramStart);

    const [searchParams, setSearchParams] = useSearchParams();

    const editoreElemRef = useRef<HTMLDivElement & {
        editor?: ace.Editor,
        slowmo?: {
            transport: GrpcWebFetchTransport,
            client: SlowmoServiceClient,
        },
    }>(null);
    const goVersionSelectorRef = useRef<HTMLSelectElement>(null);
    useEffect(() => {
        if (isNil(editoreElemRef.current?.id)) {
            throw new Error("ref to ace editor wrapper element not found")
        }
        if (isNil(goVersionSelectorRef.current?.id)) {
            throw new Error('ref to go version selector element not found')
        }
        if (!searchParams.has('goCode') || !searchParams.has('goVersion')) {
            if (!searchParams.has('goCode')) {
                const initGoCodeParam = encodeURIComponent(window.btoa(initCode));
                searchParams.append('goCode', initGoCodeParam);
            }
            if (!searchParams.has('goVersion')) {
                searchParams.append('goVersion', goVersionSelectorRef.current.value);
            }
            setSearchParams(new URLSearchParams(searchParams));
            return;
        }

        if (!isNil(editoreElemRef.current?.editor)) {
            return;
        }

        const goCodeParam = searchParams.get('goCode');
        if (isNil(goCodeParam)) {
            throw new Error('app rendered with no go code in params');
        }
        const goCode = window.atob(decodeURIComponent(goCodeParam));

        const elemId = editoreElemRef.current.id;
        const editor = ace.edit(elemId);
        editor.getSession().setMode('ace/mode/golang');
        editor.setTheme('ace/theme/solarized_light');
        editor.focus();
        editor.setValue(goCode);
        editor.clearSelection();
        editor.on('blur', () => {
            searchParams.set('goCode', encodeURIComponent(btoa(editor.getValue())));
            setSearchParams(new URLSearchParams(searchParams));
        })
        editoreElemRef.current.editor = editor;
    }, [searchParams, setSearchParams]);

    const btnElemRef = useRef<HTMLButtonElement>(null);
    useEffect(() => {
        if (isNil(btnElemRef.current?.id)) {
            throw new Error("ref to button element is null");
        }
        const btnElem = btnElemRef.current;
        if (!isAuthenticated && searchParams.has('code') && searchParams.has('state') && !btnElem.disabled) {
            btnElem.click();
        }
    }, [searchParams, isAuthenticated]);

    function setupSlowmoClient() {
        if (isNil(editoreElemRef.current)) {
            throw new Error('elemRef not set before setting up slowmo client');
        }
        if (isNil(editoreElemRef.current.slowmo)) {
            const transport = new GrpcWebFetchTransport({
                baseUrl: import.meta.env.VITE_SLOWMO_SERVER_HOSTNAME,
            });
            const client = new SlowmoServiceClient(transport);
            editoreElemRef.current.slowmo = {transport, client};
        }
    }

    async function handleClickRun() {
        setIsRequested({isRunning: false});
        if (!isAuthenticated && import.meta.env.VITE_DEV_MODE !== '1') {
            setupSlowmoClient();
            const {client} = editoreElemRef.current!.slowmo!;
            if (!searchParams.has('code')) {
                let state = '';
                try {
                    const {status, response} = await client.authn({});
                    if (status.code !== 'OK' || isNil(response.state)) {
                        throw new Error(status.detail)
                    }
                    state = response.state;
                } catch (e) {
                    outputRequestError('initiate authentication failed: ' + (e as Error).message);
                    setIsRequested(undefined);
                    return;
                }
                // Turn to GitHub for retrieving user identity.
                window.location.assign(`https://github.com/login/oauth/authorize?client_id=${import.meta.env.VITE_SLOWMO_CLIENT_ID}&redirect_uri=${window.location.href}&state=${state}`);
                return;
            } else {
                const encodedState = searchParams.get('state'), code = searchParams.get('code');
                if (isNil(encodedState) || isNil(code)) {
                    outputRequestError('missing authentication params');
                    return;
                }
                searchParams.delete('state');
                searchParams.delete('code');
                setSearchParams(new URLSearchParams(searchParams))
                try {
                    // After user identity can be retrieved, use authn endpoint
                    // to generate session token based on user identity and set
                    // Set-Cookie response header to make the client side
                    // include the token in further requests.
                    const {status} = await client.authn({params: {state: encodedState!, code: code!, channel: AuthnChannel.GITHUB}});
                    if (status.code !== 'OK') {
                        throw new Error(status.detail);
                    }
                    setIsAuthenticated(true);
                } catch (e) {
                    outputRequestError('authentication failed: ' + (e as Error).message);
                    setIsRequested(undefined);
                    return;
                }
            }
        }

        setupSlowmoClient();
        const { editor, slowmo } = editoreElemRef.current!;
        const { client } = slowmo!;
        if (isNil(editor)) {
            throw new Error('editor not set before handleClickRun');
        }
        const source = editor.getValue();
        if (isNil(goVersionSelectorRef.current)) {
            throw new Error('go version selector not mounted before handleClickRun');
        }
        const request: CompileAndRunRequest = {
            source,
            goVersion: goVersionSelectorRef.current.value,
        };
        try {
            outputRequesting();
            const stream = client.compileAndRun(request);
            setCodeLines(source.split('\n'));
            streamingLoop: for await (const msg of stream.responses) {
                switch (msg.compileAndRunOneof.oneofKind) {
                    case 'compileError':
                        outputCompilationError(msg.compileAndRunOneof.compileError.errorMessage?? '');
                        break streamingLoop;
                    case 'runtimeResult': {
                        const errMsg = msg.compileAndRunOneof.runtimeResult.errorMessage;
                        if (!isNil(errMsg)) {
                            console.log(`Program exited with error: ${errMsg}`);
                        }
                        outputProgramExit(errMsg);
                        break streamingLoop;
                    }
                    case 'runtimeOutput':
                        outputRuntimeOutput(msg.compileAndRunOneof.runtimeOutput.output?? '');
                        break
                    case 'gomaxprocs':
                        setIsRequested({isRunning: true});
                        outputProgramStart();
                        initThreads(msg.compileAndRunOneof.gomaxprocs);
                        break;
                    case 'runEvent': {
                        const runEvent = msg.compileAndRunOneof.runEvent;
                        console.debug('run event of type ', runEvent.probeEventOneof.oneofKind);
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
                    }
                    default:
                        console.warn(`unknown stream message type: ${msg.compileAndRunOneof.oneofKind}`);
                }
            }
        } catch (e) {
            outputRequestError((e as Error).message);
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

    function handleGoVersionSelectionChange(event: ChangeEvent<HTMLSelectElement>) {
        searchParams.set('goVersion', event.target.value);
        setSearchParams(new URLSearchParams(searchParams));
    }

    return (
        <div className='code-panel'>
            <div id="banner">
                <h1 id='head'>Go Slowmo</h1>
                <GoVersionSelector onChange={handleGoVersionSelectionChange} ref={goVersionSelectorRef}></GoVersionSelector>
                <CompileAndRunButton onClick={handleClickRun} ref={btnElemRef}></CompileAndRunButton>
            </div>
            <div ref={editoreElemRef} className='golang-editor' id='ace-editor-wrapper'></div>
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
        <div className='code-panel code-panel-running'>
            <div id="banner">
                <h1 id='head'>Go Slowmo</h1>
                <GoVersionSelector></GoVersionSelector>
                <CompileAndRunButton></CompileAndRunButton>
            </div>
            <div className='golang-editor'>
                <div className='instrumented-code-linenums'>
                    {lineNums}
                </div>
                <div className='instrumented-code'>
                    {spans}
                </div>
                <div className='instrumented-cursors'>
                    {cursors}
                </div>
            </div>
        </div>
    );
}

interface CompileAndRunButtonProps {
    onClick?: MouseEventHandler;
    ref?: Ref<HTMLButtonElement>;
}

function CompileAndRunButton({onClick, ref}: CompileAndRunButtonProps) {
    const isRequested = useBoundStore((state) => state.isRequested);
    const isRunning = !!(isRequested?.isRunning);

    return(
        <button id='compile-and-run-btn' ref={ref} className={'button-compile-and-run' + (isRunning? ' button-compile-and-run-running': '')} onClick={onClick} disabled={!isNil(isRequested)}>
            Compile & Run
        </button>
    );
}

interface GoVersionSelectorProps {
    onChange?: ChangeEventHandler;
    ref?: Ref<HTMLSelectElement>;
}

function GoVersionSelector({onChange, ref}: GoVersionSelectorProps) {
    const isRequested = useBoundStore((state) => state.isRequested);
    const [searchParams] = useSearchParams();

    const goVersionOptions = ((import.meta.env.VITE_GO_VERSIONS as string)?? '')
    .split(' ')
    .sort()
    .reverse()
    .map((goVersion) => {
        return (
            <option value={goVersion} key={goVersion}>Go {goVersion}</option>
        )
    });
    return (
        <select id='go-version-selector' onChange={onChange} ref={ref} className='go-version-select' value={searchParams.get('goVersion')?? undefined} disabled={!isNil(isRequested)}>
            {goVersionOptions}
        </select>
    );
}
