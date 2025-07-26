import * as ace from 'brace';
import 'brace/mode/golang';
import 'brace/theme/solarized_light';
import { useEffect, useRef, type MouseEventHandler } from 'react';
import { SlowmoServiceClient } from '../../proto/slowmo.client';
import { GrpcWebFetchTransport } from '@protobuf-ts/grpcweb-transport';
import { CompileAndRunRequest } from '../../proto/slowmo';

export default function AceEditorWrapper() {
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
        editor.setValue('// Go code');
        editor.clearSelection();
        elemRef.current.editor = editor;
    })

    async function onClickRun() {
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
        var request: CompileAndRunRequest = {
            source: editor.getValue(),
        };
        const stream = client.compileAndRun(request);
        for await (const msg of stream.responses) {
            switch (msg.compileAndRunOneof.oneofKind) {
                case 'compileError':
                    console.log('compilation returns error: ', msg.compileAndRunOneof.compileError.errorMessage);
                    break;
                case 'runEvent':
                    console.log('run event of type ', msg.compileAndRunOneof.runEvent.probeEventOneof.oneofKind);
                    break;
                case 'runtimeError':
                    console.log('runtime error: ', msg.compileAndRunOneof.runtimeError.errorMessage);
                    break;
                case 'runtimeOutput':
                    console.log('runtime output: ', msg.compileAndRunOneof.runtimeOutput.output)
                    break
                default:
                    console.log('unexpected stream message type: ', msg.compileAndRunOneof.oneofKind);
            }
        }
    }

    return (
        <div className='ace-editor-wrapper'>
            <div id="banner">
                <div id='head'>Go Runtime in Slowmo</div>
                <Button id='button-run' onClick={onClickRun}>Run</Button>
            </div>
            <div ref={elemRef} id='golang-editor'></div>
        </div>
    );
}

interface RunButtonProps {
    id: string,
    onClick: MouseEventHandler,
    children: string,
}

function Button({id, onClick, children}: RunButtonProps) {
    return (
        <button id={id} onClick={onClick}>
            {children}
        </button>
    );
}