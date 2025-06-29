import * as ace from 'brace';
import 'brace/mode/golang';
import 'brace/theme/solarized_light';
import { useEffect, useRef, type MouseEventHandler } from 'react';

export default function AceEditorWrapper() {
    const elemRef = useRef<HTMLDivElement & {
        editor?: ace.Editor,
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

    function onClickRun() {
        var editor = elemRef.current?.editor;
        if (!editor) {
            throw new Error("ace editor wrapper has no initialized editor")
        }
        // console.log(editor.getValue());
        // Call slowmo service.
    }

    return (
        <div className='ace-editor-wrapper'>
            <div id="banner">
                <div id='head'>Go Runtime Presented in Slowmo</div>
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