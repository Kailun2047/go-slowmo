import * as ace from 'brace';
import 'brace/mode/golang';
import 'brace/theme/solarized_light';
import { useEffect, useRef } from 'react';

export default function AceEditorWrapper() {
    const elemRef = useRef<any>(null); // TODO: improve typing.
    useEffect(() => {
        const elemId = elemRef.current.id;
        var editor = ace.edit(elemId);
        editor.getSession().setMode('ace/mode/golang');
        editor.setTheme('ace/theme/solarized_light');
        // Set initial content of the editor.
        editor.setValue('// Go code');
        editor.clearSelection();
    })
    return <div ref={elemRef} id='golang-editor' className='ace-editor-wrapper'></div>;
}